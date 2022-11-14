def create_one_big_chunk(body_size: int) -> str:
    return "\r\n".join(["%x" % body_size, "x" * body_size, "0", "", ""])


def create_many_big_chunks(body_size: int) -> str:
    chunks = 2**3
    chunk = "x" * int(body_size / chunks)
    return "".join("%X\r\n%s\r\n" % (len(chunk), chunk) for _ in range(chunks)) + "0\r\n\r\n"
