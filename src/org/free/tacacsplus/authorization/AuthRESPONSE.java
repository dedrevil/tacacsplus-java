package org.free.tacacsplus.authorization;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import org.free.tacacsplus.Bytes;
import org.free.tacacsplus.Header;
import org.free.tacacsplus.Tacacs;

public class AuthRESPONSE {
	public byte FLAG_NOECHO;
	public byte RESPONSE_status;
	public byte RESPONSE_arg_cnt;
	public byte[] servermsgLen;
	public byte[] dataLen;
	public final Tacacs tacacs;
	String argumentList;
	ArrayList<Integer> arguments = new ArrayList<Integer>();

	public AuthRESPONSE(Tacacs tac) {
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
		this.RESPONSE_status = body[0];
		this.RESPONSE_arg_cnt = body[1];
		if (RESPONSE_status == 1) {
			this.setServerMsgLen(body[2], body[3]);
			this.setDataLen(body[4], body[5]);
			this.setArgLength(body);
			this.setArgumentList(body);
		} else if (RESPONSE_status == 17) {
			this.setError(body);
		}

	}

	public String getError() {
		return this.argumentList;
	}

	public void setError(byte[] temp) {
		byte[] temp1 = new byte[48];
		for (int i = 0; i < 48; i++) {
			temp1[i] = temp[i + 6];
		}
		this.argumentList = new String(temp1);
	}

	public byte getStatus() {
		return this.RESPONSE_status;
	}

	public byte getArgCount() {
		return this.RESPONSE_arg_cnt;
	}

	public byte[] getDataLen() {
		return this.dataLen;
	}

	public void setDataLen(byte temp, byte temp1) {
		this.dataLen[0] = temp;
		this.dataLen[1] = temp1;
	}

	public void setServerMsgLen(byte temp, byte temp1) {
		this.servermsgLen[0] = temp;
		this.servermsgLen[1] = temp1;
	}

	public byte[] getServerMsgLen() {
		return servermsgLen;
	}

	public void setArgumentList(byte[] temp) {
		byte[] temp1 = new byte[temp.length - getArgCount() - 6];
		for (int i = 0; i < temp.length - getArgCount() - 6; i++) {
			temp1[i] = temp[i + 7];
		}
		this.argumentList = new String(temp1);
	}

	public String getArgumentList() {
		return argumentList;
	}

	public ArrayList<Integer> getArgLength() {
		return this.arguments;
	}

	public void setArgLength(byte[] temp) {
		for (int i = 0; i < getArgCount(); i++) {
			arguments.add(Bytes.BytetoInt(temp[i + 6]));
		}

	}

}