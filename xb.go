package xb

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

var b64 = base64.NewEncoding("Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe")

func Encode(params, postData string, userAgent string, timestamp uint32) string {
	uaKey := []byte{0, 1, 14}
	listKey := []byte{255}
	fixed := uint32(3845494467)
	md5Params := stdMd5Enc(stdMd5Enc([]byte(params)))
	md5PostData := stdMd5Enc(stdMd5Enc([]byte(postData)))
	md5UA := stdMd5Enc([]byte(base64.StdEncoding.EncodeToString(stdRc4Enc(uaKey, []byte(userAgent)))))

	// 等待加密列表
	list := make([]byte, 0, 19)
	list = append(list, byte(64))
	list = append(list, uaKey...)
	list = append(list, md5Params[14:16]...)
	list = append(list, md5PostData[14:16]...)
	list = append(list, md5UA[14:16]...)
	list = binary.BigEndian.AppendUint32(list, timestamp)
	list = binary.BigEndian.AppendUint32(list, fixed)
	list = append(list, xorKey(list))

	enc := make([]byte, 0, 21)
	enc = append(enc, byte(2))
	enc = append(enc, listKey...)
	enc = append(enc, stdRc4Enc(listKey, list)...)

	return b64.EncodeToString(enc)
}

type Info struct {
	Logo       byte
	Key        []byte
	ParamsHash []byte
	DataHash   []byte
	UAHash     []byte
	Ts         uint32
	Fixed      uint32
	XorHash    byte
}

func Decode(xb string) (*Info, error) {
	dec, err := b64.DecodeString(xb)
	if err != nil {
		return nil, err
	}
	if len(dec) != 21 {
		return nil, errors.New("xb no 21")
	}
	dec = dec[2:]
	dec = stdRc4Enc([]byte{255}, dec)
	return &Info{
		Logo:       dec[0],
		Key:        dec[1:4],
		ParamsHash: dec[4:6],
		DataHash:   dec[6:8],
		UAHash:     dec[8:10],
		Ts:         binary.BigEndian.Uint32(dec[10:14]),
		Fixed:      binary.BigEndian.Uint32(dec[14:18]),
		XorHash:    dec[18],
	}, nil
}

func stdMd5Enc(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func stdRc4Enc(key []byte, plainText []byte) []byte {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil
	}
	res := make([]byte, len(plainText))
	cipher.XORKeyStream(res, plainText)
	return res
}

func rc4Enc(key []byte, plainText []byte) []byte {
	sBox := make([]byte, 256)
	for i := 0; i < 256; i++ {
		sBox[i] = byte(i)
	}

	index := byte(0)
	for i := 0; i < 256; i++ {
		k := key[i%len(key)]
		index = byte(uint32(index+sBox[i]+k) % 256)
		temp := sBox[i]
		sBox[i] = sBox[index]
		sBox[index] = temp
	}

	index = byte(0)
	i := 0
	cipherText := make([]byte, 0)
	for _, ch := range plainText {
		i = (i + 1) % 256
		index = byte(uint32(index+sBox[i]) % 256)
		sBox[i], sBox[index] = sBox[index], sBox[i]
		keyStream := sBox[byte(uint32(sBox[i]+sBox[index])%256)]
		cipherText = append(cipherText, ch^keyStream)
	}
	return cipherText
}

func xorKey(list []byte) byte {
	if len(list) == 0 {
		return 0
	}
	if len(list) == 1 {
		return list[0]
	}
	key := list[0]
	for i := 1; i < len(list); i++ {
		key ^= list[i]
	}
	return key
}
