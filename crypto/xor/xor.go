package xor

// XorKey : struct where the key is stocked
type XorKey struct {
	Key []byte
}

// Encrypt : Encrypt the data
func (this *XorKey) Encrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := 0; i < len(encrypted); i++ {
		encrypted[i] = data[i] ^ this.Key[i%len(this.Key)]
	}
	return encrypted
}

// Decrypt : Decrypt the data
func (this *XorKey) Decrypt(data []byte) []byte {
	return this.Encrypt(data)
}
