package hashing

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHasher(t *testing.T) {
	authOpts := make(map[string]string)

	hasher := NewHasher(authOpts, "")

	_, ok := hasher.(pbkdf2Hasher)
	assert.True(t, ok)

	authOpts = make(map[string]string)
	authOpts["hasher"] = Pbkdf2Opt
	hasher = NewHasher(authOpts, "")

	pHasher, ok := hasher.(pbkdf2Hasher)

	assert.True(t, ok)
	assert.Equal(t, defaultPBKDF2Algorithm, pHasher.algorithm)
	assert.Equal(t, defaultPBKDF2KeyLen, pHasher.keyLen)
	assert.Equal(t, defaultPBKDF2Iterations, pHasher.iterations)
	assert.Equal(t, defaultPBKDF2SaltSize, pHasher.saltSize)
	assert.Equal(t, Base64, pHasher.saltEncoding)

	// Check that options are set correctly.
	authOpts = make(map[string]string)
	authOpts = map[string]string{
		"hasher":               Pbkdf2Opt,
		"hasher_algorithm":     SHA256,
		"hasher_keylen":        "24",
		"hasher_iterations":    "100",
		"hasher_salt_size":     "30",
		"hasher_salt_encoding": UTF8,
	}
	hasher = NewHasher(authOpts, "")

	pHasher, ok = hasher.(pbkdf2Hasher)
	assert.True(t, ok)
	assert.Equal(t, SHA256, pHasher.algorithm)
	assert.Equal(t, 24, pHasher.keyLen)
	assert.Equal(t, 100, pHasher.iterations)
	assert.Equal(t, 30, pHasher.saltSize)
	assert.Equal(t, UTF8, pHasher.saltEncoding)

	authOpts = make(map[string]string)
	authOpts["hasher"] = Argon2IDOpt
	hasher = NewHasher(authOpts, "")

	aHasher, ok := hasher.(argon2IDHasher)

	assert.True(t, ok)
	assert.Equal(t, defaultArgon2IDIterations, aHasher.iterations)
	assert.Equal(t, defaultArgon2IDKeyLen, aHasher.keyLen)
	assert.Equal(t, defaultArgon2IDMemory, aHasher.memory)
	assert.Equal(t, defaultArgon2IDParallelism, aHasher.parallelism)
	assert.Equal(t, defaultArgon2IDSaltSize, aHasher.saltSize)

	authOpts = make(map[string]string)
	authOpts = map[string]string{
		"hasher":             Argon2IDOpt,
		"hasher_iterations":  "100",
		"hasher_keylen":      "24",
		"hasher_memory":      "1024",
		"hasher_parallelism": "4",
		"hasher_salt_size":   "24",
	}
	hasher = NewHasher(authOpts, "")

	aHasher, ok = hasher.(argon2IDHasher)

	assert.True(t, ok)
	assert.Equal(t, 100, aHasher.iterations)
	assert.Equal(t, 24, aHasher.keyLen)
	assert.Equal(t, uint32(1024), aHasher.memory)
	assert.Equal(t, uint8(4), aHasher.parallelism)
	assert.Equal(t, 24, aHasher.saltSize)

	authOpts = make(map[string]string)
	authOpts["hasher"] = BcryptOpt
	hasher = NewHasher(authOpts, "")

	bHasher, ok := hasher.(bcryptHasher)
	assert.True(t, ok)
	assert.Equal(t, bHasher.cost, defaultBcryptCost)

	// Check that options are set correctly.
	authOpts = make(map[string]string)
	authOpts = map[string]string{
		"hasher":      BcryptOpt,
		"hasher_cost": "15",
	}
	hasher = NewHasher(authOpts, "")

	bHasher, ok = hasher.(bcryptHasher)
	assert.True(t, ok)
	assert.Equal(t, 15, bHasher.cost)

	// Values that don't fit in an int must fall back to the defaults instead of wrapping.
	if strconv.IntSize == 32 {
		hasher = NewHasher(map[string]string{"hasher": BcryptOpt, "hasher_cost": "4294967300"}, "")
		bHasher, ok = hasher.(bcryptHasher)
		assert.True(t, ok)
		assert.Equal(t, defaultBcryptCost, bHasher.cost)

		hasher = NewHasher(map[string]string{"hasher_iterations": "4294967396"}, "")
		pHasher, ok = hasher.(pbkdf2Hasher)
		assert.True(t, ok)
		assert.Equal(t, defaultPBKDF2Iterations, pHasher.iterations)
	}
}

func TestMalformedHashes(t *testing.T) {
	// Not the password of the valid hashes below, so any match is a bypass.
	password := "wrong-password"
	pbkdf2Hasher := NewPBKDF2Hasher(defaultPBKDF2SaltSize, defaultPBKDF2Iterations, defaultPBKDF2Algorithm, Base64, defaultPBKDF2KeyLen)
	argon2Hasher := NewArgon2IDHasher(defaultArgon2IDSaltSize, defaultArgon2IDIterations, defaultArgon2IDKeyLen, defaultArgon2IDMemory, defaultArgon2IDParallelism)

	pbkdf2Hashes := map[string]string{
		"Empty":                    "",
		"NoSeparator":              "plaintext",
		"OlderFormatTruncated":     "PBKDF2$sha512$100000",
		"OlderFormatNoHash":        "PBKDF2$sha512$100000$c2FsdA==",
		"PHCTruncated":             "$pbkdf2-sha512$i=10000,l=32",
		"PHCOptionWithoutValue":    "$pbkdf2-sha512$i$/DsNR8DBuoF/MxzLY+QVaw$YNfYNfT+6yT2blLrXKKR8Ll+aesgHYqSOtFTBsyscRM",
		"PHCUndecodableHash":       "$pbkdf2-sha512$i=10000,l=32$/DsNR8DBuoF/MxzLY+QVaw$!!!!",
		"PHCKeyLenShorterThanHash": "$pbkdf2-sha512$i=10000,l=16$/DsNR8DBuoF/MxzLY+QVaw$YNfYNfT+6yT2blLrXKKR8Ll+aesgHYqSOtFTBsyscRM",
		"PHCWithoutKeyLen":         "$pbkdf2-sha512$i=10000$/DsNR8DBuoF/MxzLY+QVaw$YNfYNfT+6yT2blLrXKKR8Ll+aesgHYqSOtFTBsyscRM",
	}
	for name, passwordHash := range pbkdf2Hashes {
		t.Run("PBKDF2/"+name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.False(t, pbkdf2Hasher.Compare(password, passwordHash))
			})
		})
	}

	argon2Hashes := map[string]string{
		"Empty":           "",
		"NoSeparator":     "plaintext",
		"OtherScheme":     "$pbkdf2-sha512$i=10000,l=32$/DsNR8DBuoF/MxzLY+QVaw$YNfYNfT+6yT2blLrXKKR8Ll+aesgHYqSOtFTBsyscRM",
		"EmptyHash":       "$argon2id$v=19$m=4096,t=3,p=2$c2FsdHNhbHQ$",
		"ZeroIterations":  "$argon2id$v=19$m=4096,t=0,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"ZeroParallelism": "$argon2id$v=19$m=4096,t=3,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
	}
	for name, passwordHash := range argon2Hashes {
		t.Run("Argon2ID/"+name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.False(t, argon2Hasher.Compare(password, passwordHash))
			})
		})
	}
}

func TestBcrypt(t *testing.T) {

	password := "test-password"
	hasher := NewBcryptHashComparer(10)

	passwordHash, err := hasher.Hash(password)

	assert.Nil(t, err)
	assert.True(t, hasher.Compare(password, passwordHash))
	assert.False(t, hasher.Compare("other", passwordHash))
}

func TestArgon2ID(t *testing.T) {
	password := "test-password"
	hasher := NewArgon2IDHasher(defaultArgon2IDSaltSize, defaultArgon2IDIterations, defaultArgon2IDKeyLen, defaultArgon2IDMemory, defaultArgon2IDParallelism)

	passwordHash, err := hasher.Hash(password)

	assert.Nil(t, err)
	assert.True(t, hasher.Compare(password, passwordHash))
	assert.False(t, hasher.Compare("other", passwordHash))
}

func TestPBKDF2(t *testing.T) {
	password := "test-password"
	b64Hasher := NewPBKDF2Hasher(defaultPBKDF2SaltSize, defaultPBKDF2Iterations, defaultPBKDF2Algorithm, Base64, defaultPBKDF2KeyLen)
	utf8Hasher := NewPBKDF2Hasher(defaultPBKDF2SaltSize, defaultPBKDF2Iterations, defaultPBKDF2Algorithm, UTF8, defaultPBKDF2KeyLen)

	t.Run("OlderFormat", func(t *testing.T) {
		t.Run("Base64", func(t *testing.T) {
			passwordHash, err := b64Hasher.Hash(password)

			assert.Nil(t, err)
			assert.True(t, b64Hasher.Compare(password, passwordHash))
			assert.False(t, b64Hasher.Compare("other", passwordHash))
		})
		t.Run("UTF8", func(t *testing.T) {
			passwordHash, err := utf8Hasher.Hash(password)

			assert.Nil(t, err)
			assert.True(t, utf8Hasher.Compare(password, passwordHash))
			assert.False(t, utf8Hasher.Compare("other", passwordHash))
		})
	})

	t.Run("PHC-SF-Spec", func(t *testing.T) {
		passwordHash := "$pbkdf2-sha512$i=10000,l=32$/DsNR8DBuoF/MxzLY+QVaw$YNfYNfT+6yT2blLrXKKR8Ll+aesgHYqSOtFTBsyscRM"
		assert.True(t, b64Hasher.Compare(password, passwordHash))
		assert.False(t, b64Hasher.Compare("other", passwordHash))
	})
}
