package org.free.tacacsplus;

import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import org.free.tacacsplus.authentication.AuthCONT;
import org.free.tacacsplus.authentication.AuthREPLY;
import org.free.tacacsplus.authentication.AuthSTART;
import org.free.tacacsplus.authorization.AuthREQUEST;
import org.free.tacacsplus.authorization.AuthRESPONSE;

public class Tacacs {
	public static final byte AUTHEN_PASS = 1;
	public static final byte AUTHEN_FAIL = 2;
	public static final byte AUTHEN_GETDATA = 3;
	public static final byte AUTHEN_GETUSER = 4;
	public static final byte AUTHEN_GETPASS = 5;
	public static final byte AUTHEN_RESTART = 6;
	public static final byte AUTHEN_ERROR = 7;
	public static final byte AUTHEN_FOLLOW = 33;
	public static final byte ZEROBYTE = 0;
	static final byte HEADERFLAG_UNENCRYPT = 1;
	public static final byte HEADERFLAG_SINGLECON = 4;
	public static final byte VERSION_13_0 = -64;
	public static final byte VERSION_13_1 = -63;
	public static final int PORT_STANDARD = 49;
	public byte headerFlags;
	public byte[] sessionID;
	public Integer tacacsSequence;
	public Byte version;
	public Integer port;
	public String hostname;
	public byte[] secretkey;
	public Socket theSocket = null;

	AuthSTART AS;
	AuthREPLY AR;
	AuthREQUEST AREQ;
	AuthRESPONSE AREP;

	public Tacacs() {
		this.headerFlags = 0;
		this.version = new Byte((byte) (-64));
		this.port = new Integer(49);
		this.hostname = "";
		this.secretkey = "".getBytes();
	}

	public void setHostname(String Hostname) {
		this.hostname = Hostname;
	}

	public void setVersion(byte Version) {
		this.version = new Byte(Version);
	}

	public void setKey(String SecretKey) {
		this.secretkey = SecretKey.getBytes();
	}

	public void setPortNumber(int PortNumber) {
		this.port = new Integer(PortNumber);
	}

	public void Connect() throws IOException {
		this.tacacsSequence = new Integer(1);
		this.sessionID = Header.generateSessionID();
		if (this.theSocket == null)
			this.theSocket = new Socket(this.hostname, this.port.intValue());
	}

	public void CloseConnection() throws IOException {
		if (this.theSocket != null) {
			this.theSocket.close();
			this.theSocket = null;
		}
		this.sessionID = null;
	}

	public String Authorize(String User) throws Exception, IOException {
		synchronized (this.tacacsSequence) {
			this.tacacsSequence = new Integer(1);
		}
		try{
		AREQ = new AuthREQUEST(this);
		AREQ.send(User, AS);
		AREP = new AuthRESPONSE(this);
		AREP.get();
		int status = AREP.getStatus();
		if (status == 1) {
			//System.out.println("Authorized");
			//System.out.println("status: " + status);
			//displayPacket();
			if (AREP.getArgumentList().contains("acl=")){
				return AREP.getArgumentList().split("acl=")[1];
			}
			throw new Exception ("Requested ACL not found in TACACS Server");
		} else if (status == 16) {
			//System.out.println("Authorization Failed");
		} else if (status == 17) {

			//System.out.println(AREP.getError());
		}
		}catch(Exception e){
			e.printStackTrace();
		}finally{
			CloseConnection();
		}
		return null;
	}

	@SuppressWarnings("unused")
	private void displayPacket() {
		System.out.println("arg_count: " + AREP.getArgCount());
		System.out.println("Server Message Length: "
				+ Bytes.ShortBytetoInt(AREP.getServerMsgLen()));
		System.out.println("Data Length: "
				+ Bytes.ShortBytetoInt(AREP.getDataLen()));
		ArrayList<Integer> args_Len;
		args_Len = AREP.getArgLength();
		System.out.println("Arguments Length: ");
		for (int i = 0; i < args_Len.size(); i++) {
			System.out.print("argument" + ++i + " " + args_Len.get(--i));
			System.out.println();
			System.out.println("Argument List: " + AREP.getArgumentList());

		}
	}

	public synchronized boolean isAuthenticated(String Username, String Password)
			throws IOException, NoSuchAlgorithmException {
		if (Username.equals("")) {
			return false;
		}
		Connect();
		AS = new AuthSTART(this);
		AS.send(Username, Password);
		AR = new AuthREPLY(this);
		AR.get();
		boolean exitLoop = false;
		while ((AR.getStatus() != 1) && (AR.getStatus() != 2)
				&& (AR.getStatus() != 7) && (AR.getStatus() != 33)
				&& (exitLoop != true)) {
			synchronized (this.tacacsSequence) {
				int tmpSeqNum = this.tacacsSequence.intValue();
				tmpSeqNum++;
				tmpSeqNum++;
				this.tacacsSequence = new Integer(tmpSeqNum);
			}
			if (((AR.REPLY_status == 3 ? 1 : 0) | (AR.REPLY_status == 4 ? 1 : 0)) != 0) {
				AuthCONT AC = new AuthCONT(null);
				AC.send(Username);
				AR.get();
				continue;
			}
			if (AR.REPLY_status == 5) {
				AuthCONT AC = new AuthCONT(this);
				AC.send(Password);
				AR.get();
				continue;
			}
			if (AR.REPLY_status == 6) {
				synchronized (this.tacacsSequence) {
					this.tacacsSequence = new Integer(1);
				}
				AS.send(Username, Password);
				AR.get();
				continue;
			}
			if (this.tacacsSequence.intValue() > 5) {
				exitLoop = true;
				continue;
			}
			exitLoop = true;
		}
		//CloseConnection();

		return AR.REPLY_status == 1;
	}
}
