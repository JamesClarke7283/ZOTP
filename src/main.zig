const std = @import("std");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const rand = std.rand;
const CSPrng = rand.DefaultCsprng;

export fn generate_key(len: usize) ![]u8 {
    var seed: [32]u8 = undefined;
    for (&seed) |*byte| {
        byte.* = @as(u8, @intCast(@mod(std.time.timestamp(), 256)));
    }
    var rng = CSPrng.init(seed);

    var key = try std.heap.page_allocator.alloc(u8, len);
    for (key) |*byte| {
        byte.* = @as(u8, @intCast(rng.random().int(u8)));
    }
    return key;
}

export fn vernam(data: []const u8, key: []const u8) ![]u8 {
    if (key.len < data.len) {
        return error.KeyTooShort;
    }

    var cipher_text = try std.heap.page_allocator.alloc(u8, key.len);
    defer std.heap.page_allocator.free(cipher_text);

    for (key, 0..) |key_byte, i| {
        if (i < data.len) {
            cipher_text[i] = data[i] ^ key_byte;
        } else {
            cipher_text[i] = key_byte; // Use key as padding
        }
    }

    // Clone the slice to return, so it doesn't get freed when the function exits.
    var return_text = try std.heap.page_allocator.alloc(u8, key.len);
    std.mem.copy(u8, return_text, cipher_text);

    return return_text;
}

// Test cases
test "test_generate_key" {
    const len = 10;
    const key = try generate_key(len);
    defer std.heap.page_allocator.free(key);
    try expect(len == key.len);
}

test "test_xorCipher" {
    const msg = "Test Message";
    const msg_bytes = msg[0..msg.len :0];

    const key = try generate_key(20); // Key longer than message
    defer std.heap.page_allocator.free(key);

    const encrypted_msg = try vernam(msg_bytes, key);
    defer std.heap.page_allocator.free(encrypted_msg);

    const decrypted_msg = try vernam(encrypted_msg, key);
    defer std.heap.page_allocator.free(decrypted_msg);

    try expectEqualSlices(u8, msg_bytes, decrypted_msg[0..msg.len]);
}
