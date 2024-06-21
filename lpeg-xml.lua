#!/bin/env lua5.4

package.cpath="/home/m/projects/lyxml/?.so"

local lyxml = require"lyxml"

--meta = {
--  __mul = function(a, b)
--  end
--}
--
--function P(s)
--  local self = {
--  }
--  setmetatable(self, meta)
--
--  return self
--end
--
--matcher = P"stream:stream" * (A"from" + A"to" + A"version")

data = "<?xml version='1.0'?>\n"
.. "<stream:stream\n"
.. "from='juliet@im.example.com'\n"
.. "to='im.example.com'\n"
.. "version='1.0'\n"
.. "xml:lang='en'\n"
.. "xmlns='jabber:client'\n"
.. "xmlns:stream='http://etherx.jabber.org/streams;&apos;'>\n";

x = lyxml.init(data)

for i = 1, #data do
  local code, str = x:parse(data:byte(i,i))
  print(code)
  if str then print(str) end
end


--matcher:feed(data)
