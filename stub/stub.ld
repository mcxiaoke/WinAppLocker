/*
 * winlock/stub/stub.ld - 链接脚本
 *
 * 保证 .lock 输出节布局：
 *   [0]           .lock.entry   (stub_entry，builder 据此 patch EP)
 *   [next]        .lock.text    (辅助函数)
 *   [next]        .lock.tlscb   (g_stub_tls_cb_marker + stub_tls_callback)
 *   [next]        .lock.rdata   (字符串常量)
 *   [next]        .lock.data    (stub_data + 字符串 + fn)
 *
 * .lock.tlscb 必须紧跟 .lock.text 之后：marker + 函数入口连续，
 * builder 搜索 STUB_TLS_CB_MAGIC 后 +8 即 stub_tls_callback 入口偏移。
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
        KEEP(*(.lock.tlscbm))   /* stub_tls_callback 定位魔数（const 数据）*/
        KEEP(*(.lock.tlscb))     /* stub_tls_callback 函数入口 */
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
