#pragma once

/*
* @note:
* 
*	as a poc, there is a very primitive return address integrity check implemented, could be much improved
* 
*	from a practical design standpoint, it'd much more efficient to compute all the valid module base/end addresses (maybe only .text/.code section?)
*		on startup, store them, and cache them each call ( see 'GetBaseAddreses' ) for use in practice
* 
*	furthermore, this doesn't account for the fact that the dependencies are dynamically loaded so this will flag calls that are legit
*		if we make a call to a module that has not yet been loaded
* 
*/

static HANDLE WINAPI HookedOpenProcess( DWORD access, BOOL inherithandle, DWORD pid )
{
	printf( "[inline hook]: OpenProcess called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return openprocess_original( access, inherithandle, pid);
}

static BOOL WINAPI HookedCloseHandle( HANDLE handle )
{
	printf( "[inline hook]: CloseHandle called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return closehandle_original( handle );
}

static BOOL HookedSetCursorPos( int x, int y )
{
	printf( "[inline hook]: SetCursorPos called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return setcursor_original( x, y );
}

static HANDLE WINAPI HookedGetCurrentProcess( )
{
	printf( "[inline hook]: GetCurrentProcess called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return getcurrentprocess_original( );
}

static HMODULE WINAPI HookedLoadLibraryA( LPCSTR filename )
{
	printf( "[inline hook]: LoadLibraryA was called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	if ( gate::loadlibrarya )
		return loadlibrarya_original( filename );
	else
		printf( "[inline hook]: call was not authenticated, rejecting\n" );

	return nullptr;
}

static HMODULE WINAPI HookedLoadLibraryW( LPCWSTR filename )
{
	printf( "[inline hook]: LoadLibraryW was called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	if ( gate::loadlibraryw )
		return loadlibraryw_original( filename );
	else
		printf( "[inline hook]: call was not authenticated, rejecting\n" );

	return nullptr;
}

static LPVOID WINAPI HookedVirtualAllocEx(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
) {
	printf( "[inline hook]: VirtualAllocEx called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return virtualallocex_original( hProcess, lpAddress, dwSize, flAllocationType, flProtect );
}

static SIZE_T WINAPI HookedVirtualQueryEx(
	HANDLE hProcess,
	LPCVOID lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T dwLength
) {
	printf( "[inline hook]: VirtualQueryEx called\n" );

	if ( !validate_call( ( uintptr_t ) _ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return virtualqueryex_original( hProcess, lpAddress, lpBuffer, dwLength );
}

static int WINAPI HookedMessageBoxW(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType
) {
	printf( "[inline hook]: MessageBoxW called with text '%ls' and caption '%ls'\n", lpText, lpCaption );

	if ( !validate_call( ( uintptr_t )_ReturnAddress( ) ) )
		printf( "[inline hook]: failed retaddr check\n" );

	return messagebox_original( hWnd, lpText, lpCaption, uType );
}

NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
	HANDLE processhandle,
	PVOID* baseaddress,
	ULONG zerobits,
	PSIZE_T regionsize,
	ULONG allocationtype,
	ULONG protect
) {
	validate_call( ( uintptr_t ) _ReturnAddress( ) );

	return ntallocatevirtualmemory_original( processhandle, baseaddress, zerobits, regionsize, allocationtype, protect );
}