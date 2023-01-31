
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <bcrypt.h>
#include <thread>
#include <intrin.h>
#include <psapi.h>
#include <future>

#pragma comment (lib, "dbghelp.lib")
#pragma comment (lib, "ntdll.lib")

#include "syscall/syscalls.h"
#include "minhook/MinHook.h"

#include "defines.h"
#include "hooks.h"

extern "C" NTSTATUS NTAPI ZwRaiseHardError( LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response );

extern "C" void InstrumentationCallbackProxy( VOID );
extern "C" void instrumentation_callback( uintptr_t ReturnAddress, uintptr_t ReturnVal )
{
	BOOLEAN sanityCheckNt;
	BOOLEAN sanityCheckWu;
	DWORD_PTR NtdllBase;
	DWORD_PTR W32UBase;
	DWORD NtdllSize;
	DWORD W32USize;
	int cbDisableOffset;
	int instPrevSpOffset;
	int instPrevPcOffset;
#ifdef _DEBUG
	BOOLEAN SymbolLookupResult = FALSE;
	DWORD64 Displacement;
	PSYMBOL_INFO SymbolInfo;
	BYTE SymbolBuffer[ sizeof( SYMBOL_INFO ) + MAX_SYM_NAME ] = { 0 };
#endif

	uintptr_t pTEB = ( uintptr_t ) NtCurrentTeb( );

#ifdef _WIN64
	cbDisableOffset = 0x02EC;	// TEB64->InstrumentationCallbackDisabled offset
	instPrevPcOffset = 0x02D8;	// TEB64->InstrumentationCallbackPreviousPc offset
	instPrevSpOffset = 0x02E0;  // TEB64->InstrumentationCallbackPreviousSp offset
	ctx->Rip = *( ( uintptr_t* ) ( pTEB + instPrevPcOffset ) );
	ctx->Rsp = *( ( uintptr_t* ) ( pTEB + instPrevSpOffset ) );
	ctx->Rcx = ctx->R10;
	ctx->R10 = ctx->Rip;
#else
	//PTEB32 pTEB = (PTEB32)NtCurrentTeb();
	cbDisableOffset = 0x01B8;   // TEB32->InstrumentationCallbackDisabled offset
	instPrevPcOffset = 0x01B0;  // TEB32->InstrumentationCallbackPreviousPc offset
	instPrevSpOffset = 0x01B4;  // TEB32->InstrumentationCallbackPreviousSp offset
#endif

	//
	// Check TEB->InstrumentaionCallbackDisabled flag to prevent recursion.
	//
	if ( !*( ( uintptr_t* ) ( pTEB + cbDisableOffset ) ) ) {
		//
		// Disabling to prevent recursion. Do not call any 
		// Win32 APIs outside of this loop and before
		// setting the TEB->InstrumentationCallbackDisabled flag
		// 
		*( ( uintptr_t* ) ( pTEB + cbDisableOffset ) ) = 1;

#ifdef _DEBUG
		// Lookup and display the Symbol Name if found
		SymbolInfo = ( PSYMBOL_INFO ) SymbolBuffer;
		SymbolInfo->SizeOfStruct = sizeof( SYMBOL_INFO );
		SymbolInfo->MaxNameLen = MAX_SYM_NAME;

		SymbolLookupResult = SymFromAddr( ( HANDLE ) -1, ReturnAddress, &Displacement, SymbolInfo );

		if ( SymbolLookupResult )
			DebugOut( L"[+] Symbol name: %s\n", GetWC( SymbolInfo->Name ) );

#ifdef DEBUG_VERBOSE
#ifdef _WIN64
		DebugOut( L"[d] CTX->Rip: 0x%016Ix\n", ctx->Rip );
#endif
		DebugOut( L"[d] ReturnAddress: 0x%016Ix\n", ReturnAddress );
		DebugOut( L"[d] ReturnVal: 0x%016Ix\n", ReturnVal );
#endif
#endif

		// Get pointers to DLL base addresss & sizes
		NtdllBase = ( DWORD_PTR ) InterlockedCompareExchangePointer(
			( PVOID* ) &g_NtdllBase,
			NULL,
			NULL
		);

		W32UBase = ( DWORD_PTR ) InterlockedCompareExchangePointer(
			( PVOID* ) &g_W32UBase,
			NULL,
			NULL
		);

		NtdllSize = InterlockedCompareExchange(
			( DWORD* ) &g_NtdllSize,
			NULL,
			NULL
		);

		W32USize = InterlockedCompareExchange(
			( DWORD* ) &g_W32USize,
			NULL,
			NULL
		);

		// Check to see if the syscall came from within the DLLs
#ifdef _WIN64
		sanityCheckNt = IP_SANITY_CHECK( ctx->Rip, NtdllBase, NtdllSize );
		sanityCheckWu = IP_SANITY_CHECK( ctx->Rip, W32UBase, W32USize );
#else
		sanityCheckNt = IP_SANITY_CHECK( ReturnAddress, NtdllBase, NtdllSize );
		sanityCheckWu = IP_SANITY_CHECK( ReturnAddress, W32UBase, W32USize );
#endif

		// If the syscall did not come from the a know DLL, print a message and break.
		if ( !( sanityCheckNt || sanityCheckWu ) ) {
			DebugOut( L"[instrumentation callback]: kernel returns to unverified module\n" );
#ifdef _WIN64
			DebugOut( L"[I] CTX->Rip: 0x%016Ix\n", ctx->Rip );
#else
			DebugOut( L"[instrumentation callback]: return address: 0x%016Ix\n", ReturnAddress );
			DebugOut( L"[instrumentation callback]: return value: 0x%016Ix\n", ReturnVal );
#endif

#ifdef _DEBUG
			if ( SymbolLookupResult )
				DebugOut( L"[!] Unverified function: %s\n", GetWC( SymbolInfo->Name ) );

			// Un-commnet if you want to manually debug
			// DebugBreak();
#endif
			//// Terminate the process
			//DebugOut( L"[!] Preventing further execution!\n" );
			//ExitProcess( ERROR_INVALID_ACCESS );
		}

		// Unset TEB->InstrumentationCallbackDisabled to re-enable
		// instrumention.
		*( ( uintptr_t* ) ( pTEB + cbDisableOffset ) ) = 0;
	}
#ifdef _WIN64
	RtlRestoreContext( ctx, NULL );
#endif
}

// Code from ScyllaHide
NTSTATUS SetInstrumentationCallbackHook( HANDLE ProcessHandle, BOOL Enable )
{
	CallbackFn Callback = Enable ? InstrumentationCallbackProxy : NULL;

	// Windows 10
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo;
#ifdef _WIN64
	Info.Version = 0;
#else
	// Native x86 instrumentation callbacks don't work correctly
	BOOL Wow64Process = FALSE;
	if ( !IsWow64Process( ProcessHandle, &Wow64Process ) || !Wow64Process )
	{
		//Info.Version = 1; // Value to use if they did
		return STATUS_NOT_SUPPORTED;
	}

	// WOW64: set the callback pointer in the version field
	CallbackInfo.Version = ( ULONG ) Callback;
#endif
	CallbackInfo.Reserved = 0;
	CallbackInfo.Callback = Callback;

	return NtSetInformationProcess( ProcessHandle, ProcessInstrumentationCallback,
		&CallbackInfo, sizeof( CallbackInfo ) );
}

void install_hooks( )
{
	/* set the inline hooks */

	MH_Initialize( );

	/* works fine just spams console because it's called several times */
	//MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "GetCurrentProcess" ), &HookedGetCurrentProcess, reinterpret_cast< LPVOID* >( &getcurrentprocess_original ) );

	MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "OpenProcess" ), &HookedOpenProcess, reinterpret_cast< LPVOID* >( &openprocess_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "CloseHandle" ), &HookedCloseHandle, reinterpret_cast< LPVOID* >( &closehandle_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "LoadLibraryA" ), &HookedLoadLibraryA, reinterpret_cast< LPVOID* >( &loadlibrarya_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "LoadLibraryW" ), &HookedLoadLibraryW, reinterpret_cast< LPVOID* >( &loadlibraryw_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "VirtualAllocEx" ), &HookedVirtualAllocEx, reinterpret_cast< LPVOID* >( &virtualallocex_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "VirtualQueryEx" ), &HookedVirtualQueryEx, reinterpret_cast< LPVOID* >( &virtualqueryex_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"User32.dll" ), "MessageBoxW" ), &HookedMessageBoxW, reinterpret_cast< LPVOID* >( &messagebox_original ) );
	MH_CreateHook( GetProcAddress( GetModuleHandle( L"User32.dll" ), "SetCursorPos" ), &HookedSetCursorPos, reinterpret_cast< LPVOID* >( &setcursor_original ) );

	/* this isn't stable for some reason */
	//MH_CreateHook( PVOID ( GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "NtAllocateVirtualMemory" ) ), &HookedNtAllocateVirtualMemory, reinterpret_cast< LPVOID* >( &ntallocatevirtualmemory_original ) );

	MH_EnableHook( MH_ALL_HOOKS );

	/* set the instrumentation callbacks */

	SymSetOptions( SYMOPT_UNDNAME );
	SymInitialize( (HANDLE)-1, NULL, TRUE );

	if ( !NT_SUCCESS( SetInstrumentationCallbackHook( (HANDLE)-1, TRUE ) ) )
		printf( "failed to initialize syscall hooks\n" );
}

void uninstall_hooks( )
{
	/* uninstall inline hooks */
	MH_DisableHook( MH_ALL_HOOKS );
	MH_Uninitialize( );

	/* @todo: instrumentation callbacks */
}

extern "C" void* internal_cleancall_wow64_gate{ nullptr };

#pragma section(".text")
__declspec( allocate( ".text" ) ) const unsigned char jmp_rbx_0[ ] = { 0x1B, 0xFF, 0x23, 0xF8 };

int main( )
{
	/* allocate bytes for our test dll rop gadget */
	jmp_rbx_0;

	/* compute base and end addresses for ntdll/win32u to cache them for integrity checks */
	GetBaseAddresses();

	/* initialize WoW64 transition (Heavens Gate) */
	internal_cleancall_wow64_gate = ( void* ) __readfsdword( 0xC0 );

	/* initialize all function call hooks */
    install_hooks( );
	
	/* program loop */

	char input[ 255 ];

	do
	{

		printf( "--------------------------------------------------------------------------------------\n" );
		printf( "you can inject your preferred dll or select from the options below\n" );
		printf( "[1] verified loadlibrary\n" );
		printf( "[2] foreign loadlibrary\n" );
		printf( "[3] winapi iat - allocate memory\n" );
		printf( "[4] winapi eat - message box\n" );
		printf( "[5] winapi eat - allocate memory\n" );
		printf( "[6] winapi eat- message box\n" );
		printf( "[7] native iat - allocate memory\n" );
		printf( "[8] native iat - message box\n" );
		printf( "[9] native eat - allocate memory\n" );
		printf( "[10] native eat - message box\n" );
		printf( "[11] direct syscall - allocate memory\n" );
		printf( "[12] direct syscall - message box\n" );
		printf( "[13] exit program\n" );
		std::cin >> input;

		switch ( atoi( input ) )
		{
		case 1: // verified loadlibrary
		{
			/* tell our hook to allow calls to go through i.e. open the gate */
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "enabling loadlibrary calls...\n" );
			gate::loadlibrarya = true;

			/* our call is now authenticated */
			printf( "calling loadlibrary...\n" );
			auto dll_module = std::async( LoadLibraryA, "example_dll.dll" );
			FreeLibrary( dll_module.get( ) );

			/* tell our hook to prevent other calls from going through i.e. close the gate */
			printf( "disabling loadlibrary calls...\n" );
			gate::loadlibrarya = false;

			break;
		}
		case 2: // foreign loadlibrary
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "calling loadlibrary...\n" );
			auto dll_module = std::async( LoadLibraryA, "example_dll.dll" );
			FreeLibrary( dll_module.get( ) );

			break;
		}
		case 3: // winapi allocate
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "allocating memory...\n" );
			void* address{ VirtualAllocEx( GetCurrentProcess(), nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
			printf( "freeing memory...\n" );
			VirtualFreeEx( GetCurrentProcess( ), address, 0, MEM_RELEASE );

			break;
		}
		case 4: // winapi msgbox
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "calling messagebox...\n" );
			MessageBoxW( NULL, L"winapi call", L"title", MB_OK );

			break;
		}
		case 5: // winapi export allocate
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "allocating memory...\n" );

			break;
		}
		case 6: // winapi export msgbox
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "calling messagebox...\n" );
			const MessageBoxW_t messagebox_export{ reinterpret_cast< MessageBoxW_t >( GetProcAddress( GetModuleHandle( L"User32.dll" ), "MessageBoxW" ) ) };
			messagebox_export( NULL, L"export address call", L"title", MB_OK );

			break;
		}
		case 7: // native allocate
		{


			break;
		}
		case 8: // native msgbox
		{
			const wchar_t* body = L"native api";
			const wchar_t* caption = L"title";

			UNICODE_STRING msgBody;
			UNICODE_STRING msgCaption;

			ULONG ErrorResponse;

			msgBody.Length = ( wcslen( body ) + 1 ) * sizeof( wchar_t );
			msgBody.MaximumLength = msgBody.Length;
			msgBody.Buffer = ( PWSTR ) body;

			msgCaption.Length = ( wcslen( caption ) + 1 ) * sizeof( wchar_t );
			msgCaption.MaximumLength = msgCaption.Length;
			msgCaption.Buffer = ( PWSTR ) caption;

			const ULONG_PTR msgParams[ ] = {
			( ULONG_PTR ) &msgBody,
			( ULONG_PTR ) &msgCaption,
			( ULONG_PTR ) ( MB_OK )
			};

			ZwRaiseHardError( 0x50000018L, 0x00000003L, 3, ( PULONG_PTR ) msgParams, NULL, &ErrorResponse );

			break;
		}
		case 9: // native export allocate
		{


			break;
		}
		case 10: // native export msgbox
		{


			break;
		}
		case 11: // syscall allocate
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "calling NtAllocateVirtualMemory...\n" );

			void* address{ };
			SIZE_T region_size{ 0x1000 };
			if ( NT_ERROR( NtAllocateVirtualMemory( GetCurrentProcess( ), &address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
			{
				printf( "could not allocate virtual memory\n" );
				break;
			}

			*reinterpret_cast< int* >( address ) = rand( );
			printf( "allocated memory at 0x%p\n", &address );
			printf( "value at address: %d\n", *reinterpret_cast< int* >( address ) );
			printf( "freeing memory...\n" );

			NtFreeVirtualMemory( address, &address, &region_size, MEM_RELEASE );

			break;
		}
		case 12: // syscall msgbox
		{
			printf( "--------------------------------------------------------------------------------------\n" );
			printf( "calling messagebox...\n" );
			syscall_msgbox( L"direct syscall", L"title" );

			break;
		}
		default:
			break;
		}

	} while ( atoi( input ) != 13 );

	/* remove the hooks */
	uninstall_hooks( );
}