const std = @import("std");
const linux = std.os.linux;

const PermissionMask = u4;

pub const ParseError = error{
    InvalidStructure,
};

/// The set of possible permissions
pub const Permission = enum(u4) {
    Private = 0b0001,
    Execute = 0b0010,
    Write = 0b0100,
    Read = 0b1000,
};

/// Represent the /proc/[pid]/maps line
pub const Map = struct {
    start: usize,
    end: usize,
    size: usize,
    permissions: PermissionMask = 0b0000,

    offset: isize,
    device: []const u8,
    index_node: u32,
    path: ?[]const u8,

    /// Parses the map line
    pub fn init(line: []const u8) ParseError!Map {
        var result: Map = undefined;
        var map_line = std.mem.tokenizeScalar(u8, line, ' ');
        const address_scope = map_line.next() orelse return ParseError.InvalidStructure;
        var address = std.mem.splitScalar(u8, address_scope, '-');
        const start = std.fmt.parseUnsigned(@TypeOf(result.start), address.first(), 16) catch return ParseError.InvalidStructure;
        const end = std.fmt.parseUnsigned(@TypeOf(result.end), address.next() orelse return ParseError.InvalidStructure, 16) catch return ParseError.InvalidStructure;

        result.start = start;
        result.end = end;
        result.size = result.end - result.start;

        const permissions = map_line.next() orelse return ParseError.InvalidStructure;
        result.permissions = 0b0000;
        for (permissions) |p| {
            result.permissions |= switch (p) {
                'r' => @enumToInt(Permission.Read),
                'w' => @enumToInt(Permission.Write),
                'x' => @enumToInt(Permission.Execute),
                'p' => @enumToInt(Permission.Private),
                else => 0b0000,
            };
        }

        const offset = map_line.next() orelse return ParseError.InvalidStructure;
        result.offset = std.fmt.parseInt(@TypeOf(result.offset), offset, 16) catch return ParseError.InvalidStructure;

        result.device = map_line.next() orelse return ParseError.InvalidStructure;

        const node = map_line.next() orelse return ParseError.InvalidStructure;
        result.index_node = std.fmt.parseUnsigned(@TypeOf(result.index_node), node, 10) catch return ParseError.InvalidStructure;

        result.path = map_line.next() orelse null;

        return result;
    }

    /// Checks whether or not the requested permission is in the mem-page
    pub fn checkPermission(self: Map, check: Permission) bool {
        return (self.permissions & @enumToInt(check)) > 0;
    }
};

/// Represents the whole /proc/[pid]/maps file
pub const Maps = struct {
    /// Lines of the map file
    maps: ?[]Map,
    /// The pid to query
    pid: linux.pid_t,
    /// The allocator
    alloc: std.heap.ArenaAllocator,

    /// Construct
    pub fn init(alloc: std.mem.Allocator, pid: linux.pid_t) Maps {
        return Maps{
            .maps = null,
            .pid = pid,
            .alloc = std.heap.ArenaAllocator.init(alloc),
        };
    }

    pub fn deinit(self: *Maps) void {
        self.alloc.deinit();
    }

    /// Parses the Map
    pub fn parse(self: *Maps) !void {
        const template = "/proc/{d}/maps";
        const size = std.fmt.count(template, .{self.pid});

        var maps_buffer: [template.len + 4]u8 = undefined;
        _ = try std.fmt.bufPrint(&maps_buffer, template, .{self.pid});
        const maps_path = maps_buffer[0..size];

        const file = try std.fs.openFileAbsolute(maps_path, .{});
        const proc_maps = try file.readToEndAlloc(self.alloc.allocator(), linux.PATH_MAX + 100);

        const new_lines = std.mem.count(u8, proc_maps, "\n");
        self.maps = try self.alloc.allocator().alloc(Map, new_lines + 1);
        var as_lines = std.mem.tokenizeScalar(u8, proc_maps, '\n');
        var i: usize = 0;
        while (as_lines.next()) |line| : (i += 1) {
            self.maps.?[i] = try Map.init(line);
        }
    }
};

test "parsing" {
    const test_parse_line =
        \\55b9b75fd000-55b9b7605000 r--p 00000000 08:20 641346                     /test/path/something/lib/proc_maps/proc_mapper
    ;

    const map = try Map.init(test_parse_line);

    const expected_map = Map{
        .start = 0x55b9b75fd000,
        .end = 0x55b9b7605000,
        .size = 0x8000,
        .permissions = @enumToInt(Permission.Read) | @enumToInt(Permission.Private),
        .offset = 0x00000000,
        .device = "08:20",
        .index_node = 641346,
        .path = "/test/path/something/lib/proc_maps/proc_mapper",
    };

    try std.testing.expectEqualDeep(expected_map, map);
}

test "check perms" {
    const expected_map = Map{
        .start = 0x55b9b75fd000,
        .end = 0x55b9b7605000,
        .size = 0x8000,
        .permissions = @enumToInt(Permission.Read) | @enumToInt(Permission.Private),
        .offset = 0x00000000,
        .device = "08:20",
        .index_node = 641346,
        .path = "/test/path/something/lib/proc_maps/proc_mapper",
    };

    try std.testing.expect(expected_map.checkPermission(Permission.Read));
    try std.testing.expect(expected_map.checkPermission(Permission.Private));
    try std.testing.expect(!expected_map.checkPermission(Permission.Execute));
    try std.testing.expect(!expected_map.checkPermission(Permission.Write));
}
