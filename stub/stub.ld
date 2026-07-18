/*
 * winlock/stub/stub.ld - 链接脚本
 *
 * 保证 .lock 输出节布局：
 *   [0]           .lock.entry  (stub_entry，builder 据此 patch EP)
 *   [next]        .lock.text    (辅助函数)
 *   [next]        .lock.data    (stub_data + 字符串 + fn)
 *
 * 其余节 (.text/.rdata/.pdata/.xdata/.reloc 等) 全部丢弃，
 * 避免与目标 PE 的节冲突。
 * objcopy -O binary -j .lock 只导出 .lock 节为 raw bytes。
 */

ENTRY(stub_entry)

SECTIONS
{
    . = 0x1000;

    .lock ALIGN(16) : SUBALIGN(16)
    {
        KEEP(*(.lock.entry))
        KEEP(*(.lock.text))
        KEEP(*(.lock.rdata))
        KEEP(*(.lock.data))
        KEEP(*(.lock.bss))
    }

    /DISCARD/ :
    {
        *(.text)
        *(.text.*)
        *(.data)
        *(.data.*)
        *(.rdata)
        *(.rdata.*)
        *(.bss)
        *(.bss.*)
        *(.pdata)
        *(.xdata)
        *(.reloc)
        *(.idata)
        *(.idata.*)
        *(.CRT*)
        *(.eh_frame*)
        *(.gcc_except_table*)
    }
}
