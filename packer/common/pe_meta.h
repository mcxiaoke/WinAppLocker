/*
 * winlock/common/pe_meta.h - PE 节名 / 属性常量
 *
 * 集中管理节名常量，阶段 5 改名时只需改这一个文件。
 *
 * 节名常量（≤8字节，PE 节名限制）
 * .payload→.rdata2 已实施（降低 DIE "compressed section" 启发式）
 * .lock→.text2 待实施（涉及 stub 架构改动，暂不动）
 */
#ifndef PE_META_H
#define PE_META_H

/* Inplace 加壳新增节名（已存在于 config.h，用 ifndef 避免重复定义） */
#ifndef WINLOCK_SECTION_NAME
#define WINLOCK_SECTION_NAME  ".lock\0\0\0"
#endif

/* Reflective 加壳 payload 节名
 * 原 ".payload" → ".rdata2"：.rdata2 看起来像扩展只读数据节，降低 DIE 启发式 */
#ifndef REFLECTIVE_SECTION_NAME
#define REFLECTIVE_SECTION_NAME ".rdata2\0"
#endif

/* 节属性常量
 *   阶段 5 会调整：
 *   - WINLOCK_LOCK_PERMS 从 ERWC 改为 ERC（0x60000020）
 *   - WINLOCK_LOCKW_PERMS 用于 stub_data 可写字段 */
#define WINLOCK_LOCK_PERMS   0xE0000020u  /* ERWC: Execute+Read+Write+Code */
#define WINLOCK_LOCKW_PERMS  0xC0000040u  /* RWI: Read+Write+Initialized */

#endif /* PE_META_H */
