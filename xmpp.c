#include <stdarg.h>
#include <stddef.h>

// TODO: script to get maximum xml depth for reading

static char *FormatXml(char *d, const char *e, const char *s, ...) {
  va_list ap;
  va_start(ap, s);
  while (*s && d < e) {
    if (*s == '%') {
      d = EncodeXml(d, e, va_arg(ap, const char*));
    }
  }
  va_end(ap);

  return d;
}

size_t xmppFormatStream(char *d, size_t n, const char *from, const char *to) {
  return d - FormatXml(d, d + n, "<?xml version='1.0'?>"
      "<stream:stream from='%' to='%'"
      " version='1.0' xml:lang='en'"
      " xmlns='jabber:client'"
      " xmlns:stream='http://etherx.jabber.org/streams'>", from, to);
}


int main() {
  char buf[1000];
}
