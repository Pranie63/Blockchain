import java.security.*;
import java.io.*;
import java.nio.file.*;
import java.security.spec.*;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Crypto {

	private static final String cryptoName = "PranavPenny(TM)";
	private static final String firstText = "A block one doest not simply maketh, but one might not but hash.";

	private static final String firstBlockFileName = "block_0.txt";

	private static final String sourceId = "CasinoRoyale";

//	private static int numberOfBlocks = 1;

	public static void main(String[] args) {
		String arg;
		for (int i = 0; i < args.length; i++) {
			arg = args[i];
			if (arg.equals("name")) {
				name();
			}
			else if (arg.equals("genesis")) {
				genesis();
			}
			else if (arg.equals("generate")) {
				generate(args[++i]);
			}
			else if (arg.equals("address")) {
				System.out.println(address(args[++i]));
			}
			else if (arg.equals("fund")) {
				fund(args[++i], Integer.parseInt(args[++i]), args[++i]);
			}
			else if (arg.equals("transfer")) {
				transfer(args[++i], args[++i], Integer.parseInt(args[++i]), args[++i]);
			}
			else if (arg.equals("balance")) {
				System.out.println(balance(args[++i]));
			}
			else if (arg.equals("verify")) {
				verify(args[++i], args[++i]);
			}
			else if (arg.equals("mine")) {
				mine(Integer.parseInt(args[++i]));
			}
			else if (arg.equals("validate")) {
				validate();
			}
		}
//		ZonedDateTime myDateObj = ZonedDateTime.now();
//		DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("E, MMM dd HH:mm:ss yyyy zzz");
//		String formattedDate = myDateObj.format(myFormatObj);
//		System.out.println("Date: " + formattedDate);
	}

	public static void name() {
		System.out.println(cryptoName);
//		return cryptoName;
	}

	public static void genesis() {
		FileWriter firstBlock;
		try {
			firstBlock = new FileWriter(firstBlockFileName);
			firstBlock.write(firstText);
			firstBlock.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		System.out.println("Genesis block created in 'block_0.txt'");
	}

	public static void generate(String fileName) {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair pair = keyGen.generateKeyPair();
			SaveKeyPair(fileName, pair);
			System.out.println("New wallet generated in '" + fileName + "'");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String address(String fileName) {
		try {
			KeyPair keys = LoadKeyPair(fileName);
			PublicKey publicKey = keys.getPublic();
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedHash = digest.digest(publicKey.getEncoded());
			String tag = getHexString(encodedHash).substring(0, 16);
//			System.out.println(tag);
			return tag;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void fund(String tag, int transferAmount, String fileName) {
		FileWriter fundingFile;
		String formattedDate;
		try {
			fundingFile = new FileWriter(fileName);
			fundingFile.write("From: " + sourceId + "\n");
			fundingFile.write("To: " + tag + "\n");
			fundingFile.write("Amount: " + transferAmount + "\n");
			ZonedDateTime myDateObj = ZonedDateTime.now();
			DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("E, MMM dd HH:mm:ss yyyy zzz");
			formattedDate = myDateObj.format(myFormatObj);
			fundingFile.write("Date: " + formattedDate);
			fundingFile.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		System.out.println("Funded wallet " + tag + " with " + transferAmount + " PranavPennies on " + formattedDate);
	}

	public static void transfer(String sourceWalletName, String destinationTag, int transferAmount, String transferFileName) {
		FileWriter transferFile;
		String formattedDate;
		String transferFileHash = "";
		try {
			transferFile = new FileWriter(transferFileName);
			transferFile.write("From: " + address(sourceWalletName) + "\n");
			transferFile.write("To: " + destinationTag + "\n");
			transferFile.write("Amount: " + transferAmount + "\n");
			ZonedDateTime myDateObj = ZonedDateTime.now();
			DateTimeFormatter myFormatObj = DateTimeFormatter.ofPattern("E, MMM dd HH:mm:ss yyyy zzz");
			formattedDate = myDateObj.format(myFormatObj);
			transferFile.write("Date: " + formattedDate);
			transferFileHash = getHashOfFile(transferFileName);
			transferFile.write("\n\n" + transferFileHash);
			transferFile.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		System.out.println("Transferred " + transferAmount + " from " + sourceWalletName + " to " + destinationTag + " and the statement to " + transferFileName + " on " + formattedDate);
	}

	public static int balance(String tag) {
		Scanner scanBlock;
		String blockFileName;
		String transactionLine;
		String[] transactionSegments;
		File transactionFile;
		int balance = 0;
		File folder;
		File[] blocks;
		try {
			folder = new File("./");
			blocks = folder.listFiles((dir, name) -> name.toLowerCase().startsWith("block_"));
			for (int i = 0; i < blocks.length; i++) {
//				blockFileName = String.format("block_%d.txt", i);
//				transactionFile = new File(blockFileName);
				transactionFile = blocks[i];
				scanBlock = new Scanner(transactionFile);
				scanBlock.nextLine();
				while (scanBlock.hasNextLine()) {
					transactionLine = scanBlock.nextLine();
					if (!transactionLine.equals("") && !(transactionLine.substring(0, 6).equals("nonce:"))) {
						transactionSegments = transactionLine.split(" ", 6);
						if (tag.equals(transactionSegments[0])) {
							balance -= Integer.parseInt(transactionSegments[2]);
						}
						if (tag.equals(transactionSegments[4])) {
							balance += Integer.parseInt(transactionSegments[2]);
						}
					}
				}
			}
			transactionFile = new File("mempool.txt");
			scanBlock = new Scanner(transactionFile);
			while (scanBlock.hasNextLine()) {
				transactionLine = scanBlock.nextLine();
				if (!transactionLine.equals("")) {
					transactionSegments = transactionLine.split(" ", 6);
					if (tag.equals(transactionSegments[0])) {
						balance -= Integer.parseInt(transactionSegments[2]);
					}
					if (tag.equals(transactionSegments[4])) {
						balance += Integer.parseInt(transactionSegments[2]);
					}
				}
			}
		}
		catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		}
		return balance;
	}

	public static void verify(String walletFileName, String transactionFileName) {
		try {
			File transactionFile = new File(transactionFileName);
			Scanner transactionScan = new Scanner(transactionFile);
			String fromTag = transactionScan.nextLine().substring(6);
			String toTag = transactionScan.nextLine().substring(4);
			String amount = transactionScan.nextLine().substring(8);
			String date = transactionScan.nextLine();
			if ((address(walletFileName).equals(fromTag) && balance(address(walletFileName)) >= Integer.parseInt(amount)) || fromTag.equals(sourceId)) {
				FileWriter mempool = new FileWriter("mempool.txt", true);
				mempool.write(fromTag + " transferred " + amount + " to " + toTag + " on " + date + "\n");
				mempool.close();
				System.out.println("The transaction in file '" + transactionFileName + "' with wallet '" + walletFileName + "' is valid, and was written to the mempool");
			}
			else {
				System.out.println("Insufficient funds");
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static void mine(int numLeadingZeros) {
		File folder;
		File[] blocks;
		try {
			folder = new File("./");
			blocks = folder.listFiles((dir, name) -> name.toLowerCase().startsWith("block_"));
			int numberOfBlocks = 1;
			int blockNumber;
			String fileName;
			for (int j = 0; j < blocks.length; j++) {
				fileName = blocks[j].getName();
				blockNumber = Integer.parseInt(fileName.substring(6, fileName.indexOf(".txt")));
				if (blockNumber + 1 > numberOfBlocks) {
					numberOfBlocks = blockNumber + 1;
				}
			}
			String prevBlockFileName = String.format("block_%d.txt", numberOfBlocks-1);
			String blockFileName = String.format("block_%d.txt", numberOfBlocks);
			String prevBlockHash = getHashOfFile(prevBlockFileName);
			FileWriter blockFile = new FileWriter(blockFileName);
			Scanner scanMemPool = new Scanner(new File("mempool.txt"));
			blockFile.write(prevBlockHash + "\n\n");
			while (scanMemPool.hasNextLine()) {
				blockFile.write(scanMemPool.nextLine() + "\n");
			}
			new PrintWriter("mempool.txt").close();
			blockFile.write("\nnonce: 0");
			blockFile.close();
			String fileContent;
			String fileUpdatedNonce;
			int i = 1;
			while (Integer.parseInt(getHashOfFile(blockFileName).substring(0, numLeadingZeros), 16) != 0) {
				fileContent = new Scanner(new File(blockFileName)).useDelimiter("\\Z").next();
				fileUpdatedNonce = fileContent.substring(0, fileContent.length()-(String.valueOf(i-1).length())).concat(String.valueOf(i));
				blockFile = new FileWriter(blockFileName);
				blockFile.write(fileUpdatedNonce);
				blockFile.close();
				i++;
			}
//			numberOfBlocks++;
			System.out.println("Mempool transactions moved to " + blockFileName + " and mined with difficulty " + numLeadingZeros + " and nonce " + (i-1));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void validate() {
		String blockFileName = "block_0.txt";
		String hash;
		File blockFile;
		Scanner blockScan;
		File folder;
		File[] blocks;
		try {
			folder = new File("./");
			blocks = folder.listFiles((dir, name) -> name.toLowerCase().startsWith("block_"));
			int i;
			for (i = 1; i < blocks.length; i++) {
				hash = getHashOfFile(blockFileName);
//				blockFileName = blocks[i].getName();
//				blockFile = new File(blockFileName);
				blockFile = blocks[i];
				blockScan = new Scanner(blockFile);
				if (!(blockScan.nextLine().equals(hash))) {
					System.out.println("False");
					i = blocks.length + 1;
				}
			}
			if (i == blocks.length) {
				System.out.println("True");
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

    // this converts an array of bytes into a hexadecimal number in
    // text format
    static String getHexString(byte[] b) {
	String result = "";
	for (int i = 0; i < b.length; i++) {
	    int val = b[i];
	    if ( val < 0 )
		val += 256;
	    if ( val <= 0xf )
		result += "0";
	    result += Integer.toString(val, 16);
	}
	return result;
    }

    // this converts a hexadecimal number in text format into an array
    // of bytes
    static byte[] getByteArray(String hexstring) {
	byte[] ret = new byte[hexstring.length()/2];
	for (int i = 0; i < hexstring.length(); i += 2) {
	    String hex = hexstring.substring(i,i+2);
	    if ( hex.equals("") )
		continue;
	    ret[i/2] = (byte) Integer.parseInt(hex,16);
	}
	return ret;
    }
    
    // This will write the public/private key pair to a file in text
    // format.  It is adapted from the code from
    // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
    static void SaveKeyPair(String filename, KeyPair keyPair) throws Exception {
	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
	PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
	PrintWriter fout = new PrintWriter(new FileOutputStream(filename));
	fout.println(getHexString(x509EncodedKeySpec.getEncoded()));
	fout.println(getHexString(pkcs8EncodedKeySpec.getEncoded()));
	fout.close();
    }

    // This will read a public/private key pair from a file.  It is
    // adapted from the code from
    // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
    static KeyPair LoadKeyPair(String filename) throws Exception {
	// Read wallet
	Scanner sin = new Scanner(new File(filename));
	byte[] encodedPublicKey = getByteArray(sin.next());
	byte[] encodedPrivateKey = getByteArray(sin.next());
	sin.close();
	// Generate KeyPair.
	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
	PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
	return new KeyPair(publicKey, privateKey);
    }

    // This will get the SHA-256 hash of a file, and is the same as
    // calling the `sha256sum` command line program
    static String getHashOfFile(String filename) throws Exception {
	byte[] filebytes = Files.readAllBytes(Paths.get(filename));
	MessageDigest digest = MessageDigest.getInstance("SHA-256");
	byte[] encodedHash = digest.digest(filebytes);
	return getHexString(encodedHash);
    }

}
