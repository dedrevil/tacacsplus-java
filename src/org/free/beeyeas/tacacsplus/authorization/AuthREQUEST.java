package org.free.tacacsplus.authorization;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import org.free.tacacsplus.Header;
import org.free.tacacsplus.Tacacs;
import org.free.tacacsplus.authentication.AuthSTART;

public class AuthREQUEST {

	public final Tacacs tacacs;
	public static byte ARGCOUNT = 0;
	public ArrayList<String> AVPair = new ArrayList<String>();

	public AuthREQUEST(Tacacs tac) {
		this.tacacs = tac;
	}

	public void send(String User, AuthSTART AS) throws IOException,
			NoSuchAlgorithmException {

		byte[] Username = User.getBytes();
		byte[] Port = "JAVA".getBytes();
		byte[] RemoteAdd = "Somewhere".getBytes();
		byte User_Len = (byte) Username.length;
		byte Port_Len = (byte) Port.length;
		byte RemoteAdd_Len = (byte) RemoteAdd.length;
		ARGCOUNT = 1;
		for (int i = 0; i < ARGCOUNT; i++) {
			AVPair.add("service=shell");
		}

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(AS.action);
		baos.write(AS.privlvl);
		baos.write(AS.authtype);
		baos.write(AS.service);
		baos.write(User_Len);
		baos.write(Port_Len);
		baos.write(RemoteAdd_Len);
		baos.write(ARGCOUNT);
		for (int i = 0; i < ARGCOUNT; i++) {
			baos.write(AVPair.get(i).getBytes().length);
		}
		baos.write(Username);
		baos.write(Port);
		baos.write(RemoteAdd);
		for (int i = 0; i < ARGCOUNT; i++) {
			baos.write(AVPair.get(i).getBytes());
		}

		byte[] body = Header.crypt(this.tacacs.version.byteValue(),
				this.tacacs.tacacsSequence.byteValue(), baos.toByteArray(),
				this.tacacs.headerFlags, this.tacacs.sessionID,
				this.tacacs.secretkey);

		baos.reset();
		byte[] header = Header.makeHeader(body, this.tacacs.version,
				Header.TYPE_AUTHORIZE, this.tacacs.tacacsSequence,
				this.tacacs.headerFlags, this.tacacs.sessionID);

		baos.write(header);
		baos.write(body);
		baos.writeTo(this.tacacs.theSocket.getOutputStream());
	}

}
