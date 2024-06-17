package main

import (
	"crypto/ecdsa" //ใช้สร้างkeyคู่ privatekey และ PublicKey

	"crypto/elliptic" //มาจาก function เส้นโค้งวงรี y^2 = x^3 +ax +b //เค้าเอาจุดบนเส้นโค้งมาบวกกัน เพื่อสร้างkeyและการencrypt
	//publickey มาจากการเอา private key ไป เข้าสมการเส้นโค้งวงรีเพื่อได้ค่า y ออกมาเป็น publickey

	"crypto/rand"   //สร้างตัวเลขสุ่มที่ปลอดภัยในการเข้ารหัส
	"crypto/sha256" //ใช้ hashข้อมูลของเรา //กรณี ECDH คือเราใช้ hash shared secret

	"fmt"
	"io"
)

func main() {
	// สร้างคีย์คู่สำหรับ Alice
	//อันนี้privAliceจะเป็นprivate key ส่วนถ้าจะเอา public key ก็เติม .PublicKey ต่อท้าย
	privAlice, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	// สร้างคีย์คู่สำหรับ Bob
	//อันนี้privBob เป็นprivate key ส่วนถ้าจะเอา public key ก็เติม .PublicKey ต่อท้าย
	privBob, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	//.Curve.ScalarMult เป็นการคูณจุดบนเส้นโค้งวงรีด้วยสเกลาร์ (scalar multiplication)
	//alice จะได้ publickey ของ bob ทีนี้พื้นฐานมันมาจากสมการเป็นจุดบนแกน x y จึงมี .X .Y
	// คำนวณ shared secret ของ Alice
	sharedSecretAlice, _ := privAlice.PublicKey.Curve.ScalarMult(privBob.PublicKey.X, privBob.PublicKey.Y, privAlice.D.Bytes())

	//bobก็ได้ publickey ของ alice ทีนี้เพื้นฐานมันมาจากสมการเป็นจุดบนแกน x y จึงมี .X .Y
	// คำนวณ shared secret ของ Bob
	sharedSecretBob, _ := privBob.PublicKey.Curve.ScalarMult(privAlice.PublicKey.X, privAlice.PublicKey.Y, privBob.D.Bytes())

	//shared secret 2ด้านจะตรงกันเหมือนกัน เพราะพื้นฐานคือเอาสองจุดมาคูณกัน สับเปลี่ยนตำแหน่งหน้าหลังก็ยังเท่ากันเหมือนเดิม
	fmt.Printf("Shared Secret Alice: %x\n", sharedSecretAlice)
	fmt.Printf("Shared Secret Bob: %x\n", sharedSecretBob)

	// ใช้ sha256 hash shared secret เพื่อมีความปลอดภัยมากขึ้น
	hash := sha256.New()
	io.WriteString(hash, string(sharedSecretAlice.Bytes())) //เขียนข้อมูลรูปแบบstringลงใน hash object
	sharedSecretHashed := hash.Sum(nil)                     //.Sum(nil)เพื่อระบุว่าไม่ต้องการผนวกค่าใดๆ ต่อท้าย

	fmt.Printf("Hashed Shared Secret: %x\n", sharedSecretHashed)

}
