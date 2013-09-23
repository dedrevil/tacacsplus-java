package org.free.tacacsplus.authentication;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.free.tacacsplus.Bytes;
import org.free.tacacsplus.Header;
import org.free.tacacsplus.Tacacs;

public class AuthCONT {
	public byte FLAG_ABORT;
	public final Tacacs tacacs;

	public AuthCONT(Tacacs tac) {
		this.tacacs = tac;
		this.FLAG_ABORT = 1;
	}

	public void send(String UserMsgData) throws IOException,
			NoSuchAlgorithmException {
		byte[] UserMsg = UserMsgData.getBytes();
		byte[] CONT_data = "NONE".getBytes();
		byte CONT_Flags = 0;
		byte[] UserMsg_Len = Bytes.ShorttoBytes((short) UserMsg.length);
		byte[] CONT_data_Len = Bytes.ShorttoBytes((short) CONT_data.length);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(UserMsg_Len);
		baos.write(CONT_data_Len);
		baos.write(CONT_Flags);
		baos.write(UserMsg);
		baos.write(CONT_data);
		byte[] body = Header.crypt(this.tacacs.version.byteValue(),
				this.tacacs.tacacsSequence.byteValue(), baos.toByteArray(),
				this.tacacs.headerFlags, this.tacacs.sessionID,
				this.tacacs.secretkey);

		byte[] header = Header.makeHeader(body, this.tacacs.version,
				Header.TYPE_AUTHENTIC, this.tacacs.tacacsSequence,
				this.tacacs.headerFlags, this.tacacs.sessionID);

		baos.reset();
		baos.write(header);
		baos.write(body);
		baos.writeTo(this.tacacs.theSocket.getOutputStream());
	}

}
