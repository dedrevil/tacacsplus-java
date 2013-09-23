 package org.free.tacacsplus;
 
 public class Bytes
 {
   public static byte[] InttoBytes(int v)
   {
/* 12 */     byte[] bytes = new byte[4];
/* 13 */     bytes[0] = (byte)((v & 0xFF000000) >>> 24);
/* 14 */     bytes[1] = (byte)((v & 0xFF0000) >>> 16);
/* 15 */     bytes[2] = (byte)((v & 0xFF00) >>> 8);
/* 16 */     bytes[3] = (byte)(v & 0xFF);
/* 17 */     return bytes;
   }
 
   public static byte InttoByte(int v) {
/* 21 */     return (byte)(v & 0xFF);
   }
 
   public static byte[] ShorttoBytes(short v) {
/* 25 */     byte[] bytes = new byte[2];
/* 26 */     bytes[0] = (byte)((v & 0xFF00) >>> 8);
/* 27 */     bytes[1] = (byte)(v & 0xFF);
/* 28 */     return bytes;
   }
 
   public static int IntBytetoInt(byte[] bytes) {
/* 32 */     if (bytes.length < 4)
/* 33 */       return 0;
/* 34 */     int v = bytes[0] << 24 & 0xFF000000 | bytes[1] << 16 & 0xFF0000 | bytes[2] << 8 & 0xFF00 | bytes[3] & 0xFF;
 
/* 38 */     return v;
   }
 
   public static int IntBytetoInt(byte byte1, byte byte2, byte byte3, byte byte4) {
/* 42 */     int v = byte1 << 24 & 0xFF000000 | byte2 << 16 & 0xFF0000 | byte3 << 8 & 0xFF00 | byte4 & 0xFF;
 
/* 46 */     return v;
   }
 
   public static int ShortBytetoInt(byte[] bytes) {
/* 50 */     if (bytes.length < 2)
/* 51 */       return 0;
/* 52 */     int v = bytes[0] << 8 & 0xFF00 | bytes[1] & 0xFF;
 
/* 54 */     return v;
   }
 
   public static int ShortBytetoInt(byte byte1, byte byte2) {
/* 58 */     int v = byte1 << 8 & 0xFF00 | byte2 & 0xFF;
 
/* 60 */     return v;
   }
   public static int BytetoInt(byte byte1) {
/* 63 */     int v = byte1 & 0xFF;
/* 64 */     return v;
   }
 }