#include "thread_hijacker.h"
#include <thread>

using namespace fi;

void thread_hijacker::execute_code( const std::vector< std::uint8_t >& code ) {
	thread_handle_ = nullptr;

	if ( code.empty( ) )
		throw std::exception( "thread_hijacker::execute_code: no code given" );

	thread_handle_ = OpenThread( THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, find_thread( ) );

	if ( !thread_handle_ )
		throw std::exception( "thread_hijacker::execute_code: failed to get thread handle" );

	std::vector< std::uint8_t > shellcode( std::size( code_prologue_ ) + code.size( ) + std::size( code_epilogue_ ) );
	
	memcpy( shellcode.data( ), code_prologue_, std::size( code_prologue_ ) );
	memcpy( shellcode.data( ) + std::size( code_prologue_ ), code.data( ), code.size( ) );
	memcpy( shellcode.data( ) + std::size( code_prologue_ ) + code.size( ), code_epilogue_, std::size( code_epilogue_ ) );

	if ( SuspendThread( thread_handle_ ) == -1 )
		throw std::exception( "thread_hijacker::execute_code: failed to suspend thread" );

	try {
		auto ctx = get_thread_context( );

		ctx.Esp -= 4; // Reserve 4 bytes for return address

		// Write the return address onto the stack
		WriteProcessMemory( process_handle_, LPVOID( ctx.Esp ), &ctx.Eip, sizeof( std::uint32_t ), nullptr );

		auto code_flag = allocate_memory( sizeof( bool ), PAGE_READWRITE );

		// Write the code flag address into our shellcode
		*reinterpret_cast< std::uint32_t* >( shellcode.data( ) + std::size( code_prologue_ ) + code.size( ) + 0x4 ) = code_flag;

		ctx.Eip = allocate_memory( shellcode.size( ), PAGE_EXECUTE_READWRITE );

		// Write the shellcode into memory
		WriteProcessMemory( process_handle_, LPVOID( ctx.Eip ), shellcode.data( ), shellcode.size( ), nullptr );

		set_thread_context( ctx );
	} catch ( const std::exception& e ) {
		// Resume the thread if any error occurs and re-throw the exception
		ResumeThread( thread_handle_ );
		
		throw e;
	}

	if ( ResumeThread( thread_handle_ ) == -1 )
		throw std::exception( "thread_hijacker::execute_code: failed to resume thread" );

	// Wait for shellcode to finish
	bool code_finished = false;
	while ( !code_finished ) {
		std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
		ReadProcessMemory( process_handle_, LPCVOID( code_flag ), &code_finished, sizeof( bool ), nullptr );
	}

	free_memory( code_flag );
	free_memory( ctx.Eip );
	CloseHandle( thread_handle_ );
}

std::uint32_t thread_hijacker::find_thread( ) {
	auto process_id = GetProcessId( process_handle_ );
	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, process_id );

	if ( snapshot == INVALID_HANDLE_VALUE )
		throw std::exception( "thread_hijacker::find_thread: failed to create snapshot" );

	THREADENTRY32 te;
	te.dwSize = sizeof( te );
	for ( auto res = Thread32First( snapshot, &te ); res; res = Thread32Next( snapshot, &te ) ) {
		if ( te.th32OwnerProcessID != process_id )
			continue;

		CloseHandle( snapshot );
		return te.th32ThreadID;
	}

	CloseHandle( snapshot );
	throw std::exception( "thread_hijacker::find_thread: failed to find compatible thread" );
}

CONTEXT thread_hijacker::get_thread_context( ) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;

	if ( !GetThreadContext( thread_handle_, &ctx ) )
		throw std::exception( "thread_hijacker::get_thread_context: failed to get context" );

	return ctx;
}

void thread_hijacker::set_thread_context( const CONTEXT& ctx ) {
	if ( !SetThreadContext( thread_handle_, &ctx ) )
		throw std::exception( "thread_hijacker::set_thread_context: failed to set context" );
}

std::uintptr_t thread_hijacker::allocate_memory( std::uint32_t size, std::uint32_t alloc_flags ) {
	auto alloc = VirtualAllocEx( process_handle_, nullptr, size, MEM_RESERVE | MEM_COMMIT, alloc_flags );

	if ( !alloc )
		throw std::exception( "thread_hijacker::allocate_memory: failed to allocate memory" );

	return std::uintptr_t( alloc );
}

void thread_hijacker::free_memory( std::uintptr_t address ) {
	if ( !VirtualFreeEx( process_handle_, LPVOID( address ), 0, MEM_RELEASE ) )
		throw std::exception( "thread_hijacker::free_memory: failed to free memory" );
}