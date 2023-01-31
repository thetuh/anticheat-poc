include ksamd64.inc
include CallConv.inc
.686

.model flat
public _InstrumentationCallbackProxy

assume fs:nothing
extern _instrumentation_callback:PROC

.code
_InstrumentationCallbackProxy PROC

    push    esp                         ; back-up ESP, ECX, and EAX to restore them
    push    ecx
    push    eax
    mov     eax, 1                      ; set EAX to 1 for comparison
    cmp     fs:1b8h, eax                ; see if the recurion flag has been set
    je      resume                      ; jump and restore the registers if it has and resume
    pop     eax
    pop     ecx
    pop     esp
    mov     fs:1b0h, ecx                ; InstrumentationCallbackPreviousPc
    mov     fs:1b4h, esp                ; InstrumentationCallbackPreviousSp
    
    pushad                              ; push registers to stack
    pushfd                              ; push flags to the stack
    cld                                 ; clear direction flag
    
    push    eax                         ; return value
    push    ecx                         ; return address
    call    _instrumentation_callback
    add     esp, 08h                    ; correct stack postion

    popfd                               ; restore stored flags
    popad                               ; restore stored registers

    mov     esp, fs:1b4h                ; restore ESP
    mov     ecx, fs:1b0h                ; restore ECX
    jmp     ecx                         ; resume execution
resume:
    pop     eax
    pop     ecx
     pop     esp
    jmp     ecx

_InstrumentationCallbackProxy ENDP

assume fs:error
end