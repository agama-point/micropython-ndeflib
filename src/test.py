import undef


test_data = b'\x91\x01\x15T\x02entest text record 1Q\x01\x15T\x02entest text record 2'

def main():
    print("Test of uNDEF library")
    data = undef.message_decoder(test_data)
    for r in data:
        print(r)


if __name__ == "__main__":
    main()
