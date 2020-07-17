#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>

namespace fi {
	class thread_hijacker {
	public:
		// The supplied handle needs the following rights: 
		// PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
		thread_hijacker( HANDLE process_handle ) : process_handle_( process_handle ) { };

		// This function will not return until the remote code has finished executing
		// When supplying code, no prologue/epilogue is needed, unless your function
		// needs it.
		void execute_code( const std::vector< std::uint8_t >& code );

	private:
		std::uint32_t find_thread( );
		
		CONTEXT get_thread_context( );
		void set_thread_context( const CONTEXT& ctx );

		std::uintptr_t allocate_memory( std::uint32_t size, std::uint32_t alloc_flags );
		void free_memory( std::uintptr_t address );

		HANDLE process_handle_ = nullptr, thread_handle_ = nullptr;

		std::uint8_t code_prologue_[ 2 ] = {
			0x60,	// pushad
			0x9C	// pushf
		};

		std::uint8_t code_epilogue_[ 10 ] = {
			0x9D,										// popf
			0x61,										// popad
			0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,	// mov [finished_flag], 0x1
			0xC3										// ret
		};
	};
} // namespace fi