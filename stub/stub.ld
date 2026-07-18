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
 * VMA 设置：
 *   Makefile 用 --image-base=0x10000，stub.ld 必须让 .lock 节 RVA 为正常值。
 *   `. = 0x11000` 设置 VMA=0x11000，RVA = VMA - ImageBase = 0x1000。
 *   若误用 `. = 0x1000`，RVA = 0x1000 - 0x10000 = 负数 → 溢出成 0xFFFF1000。
 *
 * .reloc 节保留：
 *   x86 stub 用绝对地址引用静态数据（非 PIC），必须生成重定位表，
 *   builder 读取 .reloc 表预先 patch stub.bin 到目标加载位置。
 *   x64 stub 用 RIP-relative 是 PIC，.reloc 为空也无影响。
 *   不能在 /DISCARD/ 中丢弃 .reloc，否则 ld 不会生成重定位目录项。
 *
 * objcopy -O binary -j .lock 只导出 .lock 节为 raw bytes（stub_xXX.bin）。
 * builder 同时需要 stub_xXX.exe 来读取 .reloc 节。
 */

ENTRY(stub_entry)

SECTIONS
{
    /* VMA = ImageBase(0x10000) + RVA(0x1000) = 0x11000，
     * 这样 RVA = 0x1000（正常值，不再是 0xFFFF1000）。
     * 必须与 Makefile 的 --image-base 保持一致。 */
    . = 0x11000;

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

    /* .reloc 节：x86 stub 的重定位表，builder 读取它来预 patch stub。
     * 必须保留，不能 /DISCARD/。紧跟 .lock 之后。 */
    .reloc ALIGN(16) :
    {
        *(.reloc)
        *(.reloc.*)
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
        *(.idata)
        *(.idata.*)
        *(.CRT*)
        *(.eh_frame*)
        *(.gcc_except_table*)
    }
}
