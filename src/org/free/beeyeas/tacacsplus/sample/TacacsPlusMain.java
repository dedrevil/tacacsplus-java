package org.free.tacacsplus.sample;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.free.tacacsplus.Tacacs;


public class TacacsPlusMain {
	public static String login(String aaaServerIp, String aaaSecret,
			int aaaServerPort, String userName, String passwd) throws Exception{
		try {
			Tacacs tacacs = new Tacacs();
			tacacs.setHostname(aaaServerIp);
			tacacs.setKey(new String(aaaSecret));

			if (aaaServerPort>0){
				tacacs.setPortNumber(aaaServerPort);
			}
			
			if (tacacs.isAuthenticated(userName, new String(passwd))) {
					String tacacsRoles = tacacs.Authorize(userName);
					return tacacsRoles;
			} else {
				throw new Exception("Failed to authenticate user : "+userName );
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			throw new Exception("Failed to authenticate user : "+userName);
		}
	}



public static void main(String args[]) throws Exception{
	try {
		String value =  login("tacacsserverip", "tacacsplusserversecret", 0, "username","password");
		System.out.println("Successfully authenticated " + value.toString());
	} catch (Exception e) {
		e.printStackTrace();
	}
}
}