package org.free.tacacsplus.authentication;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.free.tacacsplus.Header;
import org.free.tacacsplus.Tacacs;

public class AuthSTART {
	public byte ACTION_LOGIN;
	public byte ACTION_CHPASS;
	public byte ACTION_SENDAUTH;
	public byte AUTHTYPE_ASCII;
	public byte AUTHTYPE_PAP;
	public byte AUTHTYPE_CHAP;
	public byte AUTHTYPE_ARAP;
	public byte AUTHTYPE_MSCHAP;
	public byte PRIVLVL_MAX;
	public byte PRIVLVL_MIN;
	public byte SERVICE_NONE;
	public byte SERVICE_LOGIN;
	public byte SERVICE_ENABLE;
	public byte SERVICE_PPP;
	public byte action;
	public byte authtype;
	public byte privlvl;
	public byte service;
	public final Tacacs tacacs;

	public AuthSTART(Tacacs tac) {
		this.tacacs = tac;
		AuthSTART_init();
	}

	public void AuthSTART_init() {
		this.ACTION_LOGIN = 1;
		this.ACTION_CHPASS = 2;
		this.ACTION_SENDAUTH = 4;
		this.AUTHTYPE_ASCII = 1;
		this.AUTHTYPE_PAP = 2;
		this.AUTHTYPE_CHAP = 3;
		this.AUTHTYPE_ARAP = 4;
		this.AUTHTYPE_MSCHAP = 5;
		this.PRIVLVL_MAX = 15;
		this.PRIVLVL_MIN = 0;
		this.SERVICE_NONE = 0;
		this.SERVICE_LOGIN = 1;
		this.SERVICE_ENABLE = 2;
		this.SERVICE_PPP = 3;

		this.action = this.ACTION_LOGIN;
		this.authtype = this.AUTHTYPE_ASCII;
		this.privlvl = this.PRIVLVL_MIN;
		this.service = this.SERVICE_NONE;
	}

	public void send(String User, String Pass) throws IOException,
			NoSuchAlgorithmException {
		byte[] Username = User.getBytes();
		byte[] Data = Pass.getBytes();
		byte[] Port = "JAVA".getBytes();
		byte[] RemoteAdd = "Somewhere".getBytes();
		byte User_Len = (byte) Username.length;
		byte Port_Len = (byte) Port.length;
		byte Data_Len = (byte) Data.length;
		byte RemoteAdd_Len = (byte) RemoteAdd.length;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(this.action);
		baos.write(this.privlvl);
		baos.write(this.authtype);
		baos.write(this.service);
		baos.write(User_Len);
		baos.write(Port_Len);
		baos.write(RemoteAdd_Len);
		baos.write(Data_Len);
		baos.write(Username);
		baos.write(Port);
		baos.write(RemoteAdd);
		baos.write(Data);
		byte[] body = Header.crypt(this.tacacs.version.byteValue(),
				this.tacacs.tacacsSequence.byteValue(), baos.toByteArray(),
				this.tacacs.headerFlags, this.tacacs.sessionID,
				this.tacacs.secretkey);

		baos.reset();
		byte[] header = Header.makeHeader(body, this.tacacs.version,
				Header.TYPE_AUTHENTIC, this.tacacs.tacacsSequence,
				this.tacacs.headerFlags, this.tacacs.sessionID);

		baos.write(header);
		baos.write(body);
		baos.writeTo(this.tacacs.theSocket.getOutputStream());
	}

}
