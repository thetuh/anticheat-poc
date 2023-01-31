#pragma once

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)

#define ProcessInstrumentationCallback (PROCESSINFOCLASS)0x28
#define IP_SANITY_CHECK(ip,BaseAddress,ModuleSize) (ip > BaseAddress) && (ip < (BaseAddress + ModuleSize))
#define CEPTOR_VALID_HANDLE( h )	( ( ( ( std::uint64_t )h >> 20 ) & 0xFFF ) == 0xF0F )

namespace gate
{
	static bool loadlibrarya{ false };
	static bool loadlibraryw{ false };
	static bool loadlibraryexa{ false };
	static bool loadlibraryexw{ false };
}

static DWORD_PTR g_NtdllBase;
static DWORD_PTR g_W32UBase;

static DWORD g_NtdllSize;
static DWORD g_W32USize;

using OpenProcess_t = HANDLE( WINAPI* )( DWORD, BOOL, DWORD );
OpenProcess_t openprocess_original{ nullptr };

using CloseHandle_t = BOOL( WINAPI* )( HANDLE );
CloseHandle_t closehandle_original{ nullptr };

using LoadLibraryA_t = HMODULE( WINAPI* )( LPCSTR );
LoadLibraryA_t loadlibrarya_original{ nullptr };

using LoadLibraryW_t = HMODULE( WINAPI* )( LPCWSTR );
LoadLibraryW_t loadlibraryw_original{ nullptr };

using GetCurrentProcess_t = HANDLE( WINAPI* )( );
GetCurrentProcess_t getcurrentprocess_original{ nullptr };

using VirtualAllocEx_t = LPVOID( WINAPI* )( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
VirtualAllocEx_t virtualallocex_original{ nullptr };

using VirtualQueryEx_t = SIZE_T( WINAPI* )( HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T );
static VirtualQueryEx_t virtualqueryex_original{ nullptr };

using MessageBoxW_t = int( WINAPI* )( HWND, LPCWSTR, LPCWSTR, UINT );
static MessageBoxW_t messagebox_original{ nullptr };

using SetCursorPos_t = BOOL( WINAPI* )( int, int );
static SetCursorPos_t setcursor_original{ nullptr };

using NtAllocateVirtualMemory_t = NTSTATUS( NTAPI* )( HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG );
static NtAllocateVirtualMemory_t ntallocatevirtualmemory_original{ nullptr };

typedef void( *CallbackFn )( );

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	CallbackFn Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

VOID GetBaseAddresses( )
{
	PIMAGE_DOS_HEADER piDH;
	PIMAGE_NT_HEADERS piNH;

	g_NtdllBase = ( DWORD_PTR ) GetModuleHandle( TEXT( "ntdll.dll" ) );
	piDH = ( PIMAGE_DOS_HEADER ) g_NtdllBase;
	piNH = ( PIMAGE_NT_HEADERS ) ( g_NtdllBase + piDH->e_lfanew );

	g_NtdllSize = piNH->OptionalHeader.SizeOfImage;

	g_W32UBase = ( DWORD_PTR ) GetModuleHandle( TEXT( "win32u.dll" ) );
	if ( g_W32UBase ) {
		piDH = ( PIMAGE_DOS_HEADER ) g_W32UBase;
		piNH = ( PIMAGE_NT_HEADERS ) ( g_W32UBase + piDH->e_lfanew );
		g_W32USize = piNH->OptionalHeader.SizeOfImage;
	}
}

// https://stackoverflow.com/questions/8032080/how-to-convert-char-to-wchar-t
const wchar_t* GetWC( const char* c )
{
	const size_t cSize = strlen( c ) + 1;
	wchar_t* wc = new wchar_t[ cSize ];
	mbstowcs( wc, c, cSize );

	return wc;
}

//https://gist.github.com/syu5-gh/eaa0018ed70836b7279b
void DebugOut( const wchar_t* fmt, ... )
{
	va_list argp;
	va_start( argp, fmt );
	wchar_t dbg_out[ 4096 ];
	vswprintf_s( dbg_out, fmt, argp );
	printf( "%ls", dbg_out );
	va_end( argp );
	OutputDebugString( dbg_out );
}

bool validate_call( uintptr_t address )
{
	HMODULE hMods[ 1024 ];
	DWORD cbNeeded;

	if ( EnumProcessModules( GetCurrentProcess( ), hMods, sizeof( hMods ), &cbNeeded ) )
	{
		for ( unsigned int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ )
		{
			TCHAR szModName[ MAX_PATH ];

			if ( GetModuleFileNameEx( GetCurrentProcess( ), hMods[ i ], szModName,
				sizeof( szModName ) / sizeof( TCHAR ) ) )
			{
				const HMODULE handle{ GetModuleHandle( szModName ) };
				if ( !handle )
					continue;

				MODULEINFO mod_info{ };
				if ( !GetModuleInformation( GetCurrentProcess( ), handle, &mod_info, sizeof( MODULEINFO ) ) )
					continue;

				if ( address > ( DWORD ) mod_info.lpBaseOfDll && address <= ( DWORD ) mod_info.lpBaseOfDll + mod_info.SizeOfImage )
					return true;
			}
		}
	}

	return false;
}

void syscall_msgbox( const wchar_t* body, const wchar_t* caption )
{
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

	NtRaiseHardError( 0x50000018L, 0x00000003L, 3, ( PULONG_PTR ) msgParams, NULL, &ErrorResponse );
}