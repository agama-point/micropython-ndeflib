import undef


test_data = b'\x91\x01\x15T\x02entest text record 1Q\x01\x15T\x02entest text record 2'

def main():
    print("Test of uNDEF library")
    data = undef.message_decoder(test_data)
    for r in data:
        print(r)


    t = undef.text.TextRecord("Test encoder")
    data = undef.message_encoder([t])
    r = b''.join(data)
    print(r)

    data = undef.message_decoder(r)
    for r in data:
        print(r)


if __name__ == "__main__":
    main()
