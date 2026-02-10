build:
    zig build

test:
    zig build test

ci: build test
