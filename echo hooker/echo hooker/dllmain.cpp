#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <MinHook.h>
#include <mutex>

using ulong = DWORD;

namespace echo::structs
{
  struct OpenProcessPacket
  {
    DWORD proc_id;
    DWORD access;

    void* handle_out;

    bool success; int unk_1;
  };

  struct VerifySignature
  {
    PUCHAR pb_sig;
    ulong cb_sig;

    char pad[4];

    bool success; ulong unk;
  };

  struct ObRegisterCallback
  {
    ulong pid;
    ulong pid2;
    int64_t unk1;
    bool success;
    ulong self_proc_id;
  };

  enum class IoctlCodes : std::uint64_t
  {
    VerifySignature = 0x9e6a0594,
    ObRegisterCallback = 0x252e5e08,

  };
}
namespace echo::detours
{
  decltype(&DeviceIoControl) o_DeviceIoControl;

  HANDLE driver_handle{};

  BOOL __stdcall DeviceIoControl_hk(
    HANDLE hDevice, 
    DWORD dwIoControlCode, 
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize, 
    LPDWORD lpBytesReturned, 
    LPOVERLAPPED lpOverlapped)
  {
    using namespace echo::structs;

    static std::once_flag flag{};

    // get global handle
    //
    std::call_once(flag, [&]()
      {
        if (hDevice != INVALID_HANDLE_VALUE)
        {
          driver_handle = hDevice;
          printf("[+] Obtained driver handle: 0x%p\n\n", &driver_handle);
        }
      });

    auto ioctl_code = (IoctlCodes)dwIoControlCode;

    if (ioctl_code == IoctlCodes::VerifySignature)
    {
      printf("[INFO]: Intercepted verify signature IOCTL\n");

      auto packet = (echo::structs::VerifySignature*)lpInBuffer;

      std::wcout << "  Signature [PB]: " << packet->pb_sig << '\n';
      std::cout << "  Signature [CB]: " << packet->cb_sig << '\n';
      //std::cout << " Success [should be 0]: " << packet->success << '\n';

      std::cout << '\n';
    }
    
    if (ioctl_code == IoctlCodes::ObRegisterCallback)
    {
      printf("[INFO]: Intercepted ObRegisterCallback IOCTL\n");

      auto packet =  (echo::structs::ObRegisterCallback*)lpInBuffer;

      std::cout << "  Pid1: " << packet->pid << '\n';
      std::cout << "  Pid2: " << packet->pid2 << '\n';
     // std::cout << "Self_proc_id: " << packet->self_proc_id << '\n';

      packet->pid = 0; // dont protect echo.exe lol
      packet->success = true;

      printf("\n[+] Successfully stripped callback\n");
    }

    //{
    //  printf("\thDevice => %p\n", hDevice);
    //  printf("\tdwIoControlCode => 0x%x\n", dwIoControlCode);
    //  printf("\tlpInBuffer => %p\n", lpInBuffer);
    //  printf("\tnInBufferSize => %u\n", nInBufferSize);
    //}

    return o_DeviceIoControl(
      hDevice, 
      dwIoControlCode, 
      lpInBuffer,
      nInBufferSize, 
      lpOutBuffer, 
      nOutBufferSize, 
      lpBytesReturned, 
      lpOverlapped);
  }

  decltype(&CreateFileA) o_CreateFileA;

  HANDLE __stdcall CreateFileA_hk
  (LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile)
  {
    //printf("Enter CreateFileA Detour\n");

    //{
    //  printf("\tlpFileName => %s\n", lpFileName);
    //  printf("\tdwDesiredAccess => %x\n", dwDesiredAccess);
    //  printf("\tdwShareMode => %x\n", dwShareMode);
    //  printf("\tlpSecurityAttributes => %p\n", lpSecurityAttributes);
    //  printf("\tdwCreationDisposition => %x\n", dwCreationDisposition);
    //  printf("\tdwFlagsAndAttributes => %x\n", dwFlagsAndAttributes);
    //  printf("\thTemplateFile => %p\n", hTemplateFile);
    //}

    //printf("Calling CreateFileA original\n\n");

    return o_CreateFileA(
      lpFileName, 
      dwDesiredAccess, 
      dwShareMode, 
      lpSecurityAttributes,
      dwCreationDisposition, 
      dwFlagsAndAttributes,
      hTemplateFile);
  }
}

namespace echo::context
{
#pragma warning (disable:26812)

  bool install_hooks() noexcept
  {
    if (MH_Initialize() != MH_OK)
      return false;

    if (MH_CreateHook(&DeviceIoControl, detours::DeviceIoControl_hk, (void**)&detours::o_DeviceIoControl) != MH_OK)
      return false;

    if (MH_CreateHook(&CreateFileA, detours::CreateFileA_hk, (void**)&detours::o_CreateFileA) != MH_OK)
      return false;

    return MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
  }

#pragma warning (default:26812)

  void initialize() noexcept
  {
    {
      AllocConsole();

      _iobuf* data = { };

      freopen_s(&data, "conin$", "r", stdin);
      freopen_s(&data, "conout$", "w", stdout);
    }

    if (!install_hooks())
      MessageBoxA(nullptr, "Failed to install hooks", nullptr, 0u);
  }
}

bool __stdcall DllMain(void*, uint32_t reason, void*)
{
  using namespace echo;

  if (reason != DLL_PROCESS_ATTACH)
    return false;

  const auto thread = CreateThread(nullptr, 0ull, (LPTHREAD_START_ROUTINE)
    context::initialize, nullptr, 0ul, nullptr);

  if (thread)
    CloseHandle(thread);

  return true;
}