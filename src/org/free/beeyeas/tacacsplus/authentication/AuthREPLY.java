package org.free.tacacsplus.authentication;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;

import org.free.tacacsplus.Header;
import org.free.tacacsplus.Tacacs;

public class AuthREPLY {
	public byte FLAG_NOECHO;
	public byte REPLY_status;
	public byte REPLY_flags;
	public byte[] servermsgLen;
	public byte[] dataLen;
	public final Tacacs tacacs;

	public AuthREPLY(Tacacs tac) {
		this.tacacs = tac;
		this.FLAG_NOECHO = 1;
		this.servermsgLen = new byte[2];
		this.dataLen = new byte[2];
	}

	public void get() throws IOException, SocketException,
			NoSuchAlgorithmException {
		DataInputStream dis = null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] body = null;
		byte[] header = null;
		dis = new DataInputStream(this.tacacs.theSocket.getInputStream());
		for (int i = 0; i < 12; i++) {
			baos.write(dis.readByte());
		}
		header = baos.toByteArray();
		baos.reset();
		int Body_Len = Header.extractBodyLen(header);
		for (int i = 0; i < Body_Len; i++) {
			baos.write(dis.readByte());
		}
		byte[] tempBody = baos.toByteArray();
		byte headerVersionNumber = Header.extractVersionNumber(header);
		byte headerFlags = Header.extractFlags(header);
		byte headerSequenceNumber = Header.extractSeqNum(header);
		body = Header.crypt(headerVersionNumber, headerSequenceNumber,
				tempBody, headerFlags, this.tacacs.sessionID,
				this.tacacs.secretkey);
		this.REPLY_status = body[0];
		this.REPLY_flags = body[1];
	}

	public byte getStatus() {
		return this.REPLY_status;
	}

	public byte getFlags() {
		return this.REPLY_flags;
	}

}