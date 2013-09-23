 package org.free.tacacsplus;
 
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.util.Random;
 
 public class Header
 {
/* 14 */   public static byte TYPE_AUTHENTIC = 1;
/* 15 */   public static byte TYPE_AUTHORIZE = 2;
/* 16 */   public static byte TYPE_ACCOUNTIN = 3;
 
   public static byte[] crypt(byte versionNumber, byte sequenceNumber, byte[] body, byte headerFlags, byte[] sessionID, byte[] secretkey) throws IOException, NoSuchAlgorithmException {
/* 19 */     if (headerFlags == 1)
/* 20 */       return body;
/* 21 */     MessageDigest md = null;
/* 22 */     md = MessageDigest.getInstance("MD5");
/* 23 */     byte[] pad = null;
/* 24 */     byte[] lastPad = null;
/* 25 */     boolean keepLoop = true;
/* 26 */     while (keepLoop) {
/* 27 */       ByteArrayOutputStream baos = new ByteArrayOutputStream();
/* 28 */       baos.write(sessionID);
/* 29 */       baos.write(secretkey);
/* 30 */       baos.write(versionNumber);
/* 31 */       baos.write(sequenceNumber);
/* 32 */       if (lastPad != null)
/* 33 */         baos.write(lastPad);
/* 34 */       lastPad = md.digest(baos.toByteArray());
/* 35 */       baos.reset();
/* 36 */       if (pad != null)
/* 37 */         baos.write(pad);
/* 38 */       baos.write(lastPad);
/* 39 */       pad = baos.toByteArray();
/* 40 */       if (pad.length > body.length)
/* 41 */         keepLoop = false;
     }
/* 43 */     byte[] realBody = new byte[body.length];
/* 44 */     for (int i = 0; i < body.length; i++) {
/* 45 */       realBody[i] = Bytes.InttoByte(Bytes.BytetoInt(body[i]) ^ Bytes.BytetoInt(pad[i]));
     }
 
/* 48 */     return realBody;
   }
 
   public static byte[] makeHeader(byte[] body, Byte version, byte type, Integer tacacsSequence, byte headerFlags, byte[] sessionID) throws IOException {
/* 52 */     byte[] Body_Len = Bytes.InttoBytes(body.length);
/* 53 */     ByteArrayOutputStream baos = new ByteArrayOutputStream();
/* 54 */     baos.write(version.byteValue());
/* 55 */     baos.write(type);
/* 56 */     baos.write(tacacsSequence.byteValue());
/* 57 */     baos.write(headerFlags);
/* 58 */     baos.write(sessionID);
/* 59 */     baos.write(Body_Len);
/* 60 */     return baos.toByteArray();
   }
   public static byte extractVersionNumber(byte[] Header) {
/* 63 */     return Header[0];
   }
   public static byte extractFlags(byte[] Header) {
/* 66 */     return Header[3];
   }
   public static byte extractSeqNum(byte[] Header) {
/* 69 */     return Header[2];
   }
   static int extractSessionID(byte[] Header) {
/* 72 */     byte[] sessionID = new byte[4];
/* 73 */     sessionID[0] = Header[4];
/* 74 */     sessionID[1] = Header[5];
/* 75 */     sessionID[2] = Header[6];
/* 76 */     sessionID[3] = Header[7];
/* 77 */     int sessID = Bytes.IntBytetoInt(sessionID);
/* 78 */     return sessID;
   }
   public static int extractBodyLen(byte[] header) {
/* 81 */     byte[] length = new byte[4];
/* 82 */     length[0] = header[8];
/* 83 */     length[1] = header[9];
/* 84 */     length[2] = header[10];
/* 85 */     length[3] = header[11];
/* 86 */     int bodyLen = Bytes.IntBytetoInt(length);
/* 87 */     return bodyLen;
   }
   static byte[] generateSessionID() {
/* 90 */     Random ran = new Random(System.currentTimeMillis());
/* 91 */     return Bytes.InttoBytes(ran.nextInt());
   }
 }

