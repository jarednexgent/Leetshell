ENTRY(alignstack)
SECTIONS {
  . = __image_base__ + SIZEOF_HEADERS;
  . = ALIGN(__section_alignment__);
  .text : {
    *(.text.alignstack)
    *(.text.Main)
    *(.text*)
    *(.rdata*)
  }
}
