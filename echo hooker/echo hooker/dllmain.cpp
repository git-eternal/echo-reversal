#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <MinHook.h>
#include <mutex>
#include <fstream>
#include <TlHelp32.h>
#include <algorithm>

using ulong = DWORD;

inline std::ofstream file{ "C:\\echo_log.txt" };

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

  enum class IoctlCodes : std::uint64_t
  {
    VerifySignature = 0x9e6a0594,
    ObRegisterCallback = 0x252e5e08,
    ReadMemory = 0x60a26124,
    ObtainHandle = 0xE6224248,
    ProtectProcess = 0x25F26648
  };
}

DWORD get_process_id(LPCTSTR name)
{
  PROCESSENTRY32 pe32; HANDLE snapshot = NULL; DWORD pid = 0;

  snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (snapshot != INVALID_HANDLE_VALUE)
  {
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32))
    {
      do
      {
        std::string sName = pe32.szExeFile;

        std::transform(sName.begin(), sName.end(), sName.begin(), ::tolower);

        if (!lstrcmp(sName.c_str(), name))
        {
          pid = pe32.th32ProcessID; break;
        }

      } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
  }

  return pid;
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
          file << "[+] Obtained driver handle: 0x" << driver_handle << '\n';
        }
      });

    auto ioctl_code = (IoctlCodes)dwIoControlCode;

    if (ioctl_code == IoctlCodes::ProtectProcess)
    {
        printf("[INFO]: Intercepted protect process IOCTL\n");
        auto packet = (ProtectProcess*)lpInBuffer;

        std::cout << "PROTECTION TYPE: " << packet->prot_flag << '\n';

        packet->prot_flag = 0x0; // PsProtectedTypeNone
    }

    if (ioctl_code == IoctlCodes::VerifySignature)
    {
      printf("[INFO]: Intercepted verify signature IOCTL\n");

      auto packet = (VerifySignature*)lpInBuffer;

      file << "\n[IOCTL: VERIFY SIGNATURE] 0x" << std::hex << dwIoControlCode << std::dec << '\n';
      file << "  PB SIG: " << packet->pb_sig << '\n';
      file << "  CB SIG: " << packet->cb_sig << '\n';
      file << '\n';

      packet->pb_sig = 0;
      packet->cb_sig = 0;

      std::wcout << "  Signature [PB]: " << packet->pb_sig << '\n';
      std::cout << "  Signature [CB]: " << packet->cb_sig << '\n';
      //std::cout << " Success [should be 0]: " << packet->success << '\n';

      std::cout << '\n';
    }
    
    if (ioctl_code == IoctlCodes::ObRegisterCallback)
    {
      printf("[INFO]: Intercepted ObRegisterCallback IOCTL\n");

      auto packet =  (RegisterCallback*)lpInBuffer;

      file << "\n[IOCTL: ObRegisterCallback] 0x" << std::hex << dwIoControlCode << std::dec << '\n';
      file << "  PID1: " << packet->pid1 << '\n';
      file << "  PID2: " << packet->pid2 << '\n';
      file << "  PID3: " << packet->pid3 << '\n';
      file << "  PID4: " << packet->pid4 << '\n';
      file << '\n';

      std::cout << "  Pid1: " << packet->pid1 << '\n';
      std::cout << "  Pid2: " << packet->pid2 << '\n';
      std::cout << "  Pid3: " << packet->pid3 << '\n';
      std::cout << "  Pid4: " << packet->pid4 << '\n';
     // std::cout << "Self_proc_id: " << packet->self_proc_id << '\n';

      packet->pid1 = 0; // dont protect echo.exe lol
      packet->success = true;

      //printf("\n[+] Successfully stripped callback\n");
    }

    if (ioctl_code == IoctlCodes::ObtainHandle)
    {
      auto packet = (OpenProcessPacket*)lpInBuffer;

      file << "\n[IOCTL: OBTAIN HANDLE] 0x" << std::hex << dwIoControlCode << std::dec << '\n';
      file << "  PID: " << packet->proc_id << '\n';
      file << "  ACCESS: " << packet->access << '\n';

      std::cout << "NOTEPAD PID: " << get_process_id("notepad.exe") << '\n';

      packet->proc_id = get_process_id("notepad.exe");
    
      std::cout << "NEW JAVAW PID: " << packet->proc_id << '\n';
      file << '\n';
    }

    if (ioctl_code == IoctlCodes::ReadMemory)
    {
      auto packet = (ReadMemory*)lpInBuffer;

      file << "\n[IOCTL: READ MEMORY] 0x" << std::hex << dwIoControlCode << std::dec << '\n';
      file << "  BUFFER SIZE: " << packet->buffer_size << '\n';
      file << "  READ ADDRESS: " << packet->read_address << '\n';
      file << "  READ BUFFER: " << packet->read_buffer << '\n';
      file << "  HANDLE: " << packet->handle<< '\n';
      file << '\n';
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


    file << "\n[CREATE_FILE HOOK]:\n";
    file << "Filename: " << lpFileName << '\n';
    file << "dwDesiredAccess: 0x" << std::hex << dwDesiredAccess << std::dec << '\n';
    file << "dwShareMode: " << dwShareMode << '\n';
    file << "lpSecurityAttributes: " << lpSecurityAttributes << '\n';
    file << "dwCreationDisposition: " << dwCreationDisposition << '\n';
    file << "dwFlagsAndAttributes: " << dwFlagsAndAttributes << '\n';
    file << "hTemplateFile: " << hTemplateFile << '\n';

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