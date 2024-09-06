idf_component_register(SRCS "esp-im.c"
    "../../im.c"
    "../../../yxml.c"
    "../../../xmpp.c"
    "../../../c25519.c"
    "../../../omemo.c"
    INCLUDE_DIRS "." "../../" "../../../")
set_source_files_properties("../../../xmpp.c" "../../im.c"
    "../../../omemo.c" PROPERTIES
    COMPILE_FLAGS "-Wno-unused -Wno-pointer-sign")
