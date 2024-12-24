; x86 mode (assumed that the target function is at 0x40000000)

; 32bit relative JMPs of 5 bytes cover whole address space
0x40000000:  E9 FBFFFFBF      JMP 0x0        (EIP+0xBFFFFFFB)
0x40000000:  E9 FAFFFFBF      JMP 0xFFFFFFFF (EIP+0xBFFFFFFA)

; Shorter forms are useless in this case
; 8bit JMPs of 2 bytes cover -126 ~ +129 bytes
0x40000000:  EB 80            JMP 0x3FFFFF82 (EIP-0x80)
0x40000000:  EB 7F            JMP 0x40000081 (EIP+0x7F)
; 16bit JMPs of 4 bytes cover -32764 ~ +32771 bytes
0x40000000:  66E9 0080        JMP 0x3FFF8004 (EIP-0x8000)
0x40000000:  66E9 FF7F        JMP 0x40008003 (EIP+0x7FFF)template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(
        pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

...

// Create a hook for MessageBoxW, in disabled state.
if (MH_CreateHookApiEx(L"user32", "MessageBoxW", &DetourMessageBoxW, &fpMessageBoxW) != MH_OK)
{
    return 1;
}; x64 mode (assumed that the target function is at 0x140000000)

; 32bit relative JMPs of 5 bytes cover about -2GB ~ +2GB
0x140000000: E9 00000080      JMP 0xC0000005  (RIP-0x80000000)
0x140000000: E9 FFFFFF7F      JMP 0x1C0000004 (RIP+0x7FFFFFFF)

; Target function (Jump to the Relay Function)
0x140000000: E9 FBFF0700      JMP 0x140080000 (RIP+0x7FFFB)

; Relay function (Jump to the Detour Function)
0x140080000: FF25 FAFF0000    JMP [0x140090000 (RIP+0xFFFA)]
0x140090000: xxxxxxxxxxxxxxxx ; 64bit address of the Detour Function; Original "USER32.dll!MessageBoxW" in x64 mode
0x770E11E4: 4883EC 38         SUB RSP, 0x38
0x770E11E8: 4533DB            XOR R11D, R11D
; Trampoline
0x77064BD0: 4883EC 38         SUB RSP, 0x38
0x77064BD4: 4533DB            XOR R11D, R11D
0x77064BD7: FF25 5BE8FEFF     JMP QWORD NEAR [0x77053438 (RIP-0x117A5)]
; Address Table
0x77053438: EB110E7700000000  ; Address of the Target Function +7 (for resuming)

; Original "USER32.dll!MessageBoxW" in x86 mode
0x7687FECF: 8BFF              MOV EDI, EDI
0x7687FED1: 55                PUSH EBP
0x7687FED2: 8BEC              MOV EBP, ESP
; Trampoline
0x0014BE10: 8BFF              MOV EDI, EDI
0x0014BE12: 55                PUSH EBP
0x0014BE13: 8BEC              MOV EBP, ESP
0x0014BE15: E9 BA407376       JMP 0x7687FED4; Original "kernel32.dll!IsProcessorFeaturePresent" in x64 mode
0x771BD130: 83F9 03           CMP ECX, 0x3
0x771BD133: 7414              JE 0x771BD149
; Trampoline
; (Became a little complex, because 64 bit version of JE doesn't exist)
0x77069860: 83F9 03           CMP ECX, 0x3
0x77069863: 74 02             JE 0x77069867
0x77069865: EB 06             JMP 0x7706986D
0x77069867: FF25 1BE1FEFF     JMP QWORD NEAR [0x77057988 (RIP-0x11EE5)]
0x7706986D: FF25 1DE1FEFF     JMP QWORD NEAR [0x77057990 (RIP-0x11EE3)]
; Address Table
0x77057988: 49D11B7700000000  ; Where the original JE points.
0x77057990: 35D11B7700000000  ; Address of the Target Function +5 (for resuming)

; Original "gdi32.DLL!GdiFlush" in x86 mode
0x76479FF4: E8 DDFFFFFF       CALL 0x76479FD6
; Trampoline
0x00147D64: E8 6D223376       CALL 0x76479FD6
0x00147D69: E9 8B223376       JMP 0x76479FF9

; Original "kernel32.dll!CloseProfileUserMapping" in x86 mode
0x763B7918: 33C0              XOR EAX, EAX
0x763B791A: 40                INC EAX
0x763B791B: C3                RET
0x763B791C: 90                NOP
; Trampoline (Additional jump is not required, because this is a perfect function)
0x0014585C: 33C0              XOR EAX, EAX
0x0014585E: 40                INC EAX
0x0014585F: C3                RET; Original "kernel32.dll!GetConsoleInputWaitHandle" in x64 mode
0x771B27F0: 488B05 11790C00   MOV RAX, [0x7727A108 (RIP+0xC7911)]
; Trampoline
0x77067EB8: 488B05 49222100   MOV RAX, [0x7727A108 (RIP+0x212249)]
0x77067EBF: FF25 4BE3FEFF     JMP QWORD NEAR [0x77056210 (RIP-0x11CB5)]
; Address Table
0x77056210: F7271B7700000000  ; Address of the Target Function +7 (for resuming)

; Original "user32.dll!TileWindows" in x64 mode
0x770E023C: 4883EC 38         SUB RSP, 0x38
0x770E0240: 488D05 71FCFFFF   LEA RAX, [0x770DFEB8 (RIP-0x38F)]
; Trampoline
0x77064A80: 4883EC 38         SUB RSP, 0x38
0x77064A84: 488D05 2DB40700   LEA RAX, [0x770DFEB8 (RIP+0x7B42D)]
0x77064A8B: FF25 CFE8FEFF     JMP QWORD NEAR [0x77053360 (RIP-0x11731)]
; Address Table
0x77053360: 47020E7700000000 ; Address of the Target Function +11 (for resuming)
