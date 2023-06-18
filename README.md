# Proc Maps Parser
A simple /proc/[pid]/maps parser.

## Example Usage
```zig
var maps = Maps.init(std.heap.page_allocator, std.os.linux.getpid());
try maps.parse();
defer maps.deinit(); // always free after parse!

for(maps) |map| {
  std.testing.expect(map.checkPermission(Permission.Read));
}
```

## Tests
To test the library, just call 
`zig build test`
from this repo.
