

import com.sdt.util.file.FileUtil;
import com.sdt.util.security.Base64Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64.Decoder;

import static java.util.Base64.getDecoder;

public class ParseCert {
    public static void main(String[] args) throws Exception {
        System.out.println("请输入从ldap服务器上导出的文件（.ldif）");
        Scanner scanner = new Scanner(System.in);
        String nextLine = scanner.nextLine();
        System.out.println(nextLine);
        String ldifFilePath = nextLine.replace("\\", "\\\\");
        String desFilePath = "F:/HaveqdParseCert/";
        System.out.println("请输入从ldap上导出的吊销证书列表的文件（.crl）");
        Scanner scanner1 = new Scanner(System.in);
        String nextLine1 = scanner1.nextLine();
        String crlFilePath = nextLine1.replace("\\", "//");
        System.out.println("第一步解析ldap文件");
        System.out.println("解析ldap文件中........请耐心等待!!!");
        spliteLdif1(ldifFilePath, desFilePath);
        System.out.println("第五步删除吊销证书");
        File file1 = new File(desFilePath);        //获取其file对象
        func1(file1, obtainUnusingList(crlFilePath));
        System.out.println("第六步删除非院的文件夹内容");
        File fileEmpty = new File(desFilePath);
        deleteFiles(fileEmpty);
        fileRank(fileEmpty);
        deleteEmptyFiles(fileEmpty);
    }

    //该方法的主要作用是将ldap上导出的文件拆分为多个临时文件
    public static List<String> spliteLdif1(String ldifFilePath, String desFilePath) {
        final Decoder decoder = getDecoder();
        final Base64.Encoder encoder = Base64.getEncoder();
        List<String> organ = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(ldifFilePath));
            String temp = "";
            int flag = 0;
            String s = null;
            String name = "";
            String organName = "";
            String privice = "";
            OutputStream out = null;
            BufferedWriter bw = null;
            BufferedReader br1 = null;
            InputStream is = null;
            int conut = 0;
            while ((s = br.readLine()) != null) {
                conut++;
                if (s.isEmpty()) {
                    if (temp.isEmpty()) {

                    } else {
                        //写cer文件
                        String path = desFilePath + privice + "/" + organName + "/";
                        File filePath = new File(path);

                        if (!filePath.exists()) {
                            filePath.mkdirs();
                            out = new FileOutputStream(desFilePath + privice + "/" + organName + "/" + name + ".cer");
                        } else {
                            out = new FileOutputStream(desFilePath + privice + "/" + organName + "/" + name + "sign" + conut + ".cer");
                        }
                        if (temp == null || "".equals(temp)) {
                            continue;
                        }
                        temp = temp.replace("\\r", "").replace("\\n", "").replace(" ", "");

                        is = new ByteArrayInputStream(temp.getBytes());
                        byte[] buff = new byte[1024];
                        int len = 0;
                        while ((len = is.read(buff)) != -1) {
                            out.write(buff, 0, len);
                        }
                        is.close();
                        out.close();
                    }
                    flag = 0;
                    s = null;
                    name = "";
                    organName = "";
                    privice = "";
                } else {
                    while (flag == 0) {
                        if (s.startsWith("cn:: ")) {
                            name = new String(decoder.decode(s.split("cn:: ")[1].trim()), "UTF-8").replaceAll("\\r\\n|\\r|\\n|\\n\\r", "").replace("\\r", "").replace("\\n", "").replace(" ", "");
                        }
                        if (s.startsWith("cn: ")) { //每行中以BC开头就将其保存到一个文件中
                            name = s.split("cn: ")[1].trim().replace("\\r", "").replaceAll("\\r\\n|\\r|\\n|\\n\\r", "").replace("\\n", "").replace(" ", "");
                        }
                        if (s.startsWith("o::")) {
                            privice = new String(decoder.decode(s.split("o::")[1].trim()), "UTF-8").replaceAll("\\r\\n|\\r|\\n|\\n\\r", "").replace("\\r", "").replace("\\n", "").replace(" ", "");
                        }
                        if (s.startsWith("ou:: ")) {
                            organName = new String(decoder.decode(s.split("ou:: ")[1].trim()), "UTF-8").replaceAll("\\r\\n|\\r|\\n|\\n\\r", "").replace(" ", "");
                        }
                        if (s.startsWith("ou: ")) {
                            organName = s.split("ou: ")[1].trim().replaceAll("\\r\\n|\\r|\\n|\\n\\r", "").replace(" ", "").replace("、", "");
                        }
                        if (s.startsWith("userCertificate;binary::")) {
                            flag = 1;
                        }
                        break;
                    }
                    while (flag == 1) {
                        if (s.startsWith("street")) {
                            flag = 0;
                            continue;
                        }
                        if (s.startsWith("userCertificate;binary::")) {
                            temp = s.split("userCertificate;binary::")[1].trim();
                            break;
                        }
                        temp = temp + s;
                        break;
                    }
                }
            }
            return organ;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return organ;
    }

    /**
     * 该方法是根据吊销文件获取吊销列表
     *
     * @param filePath
     * @return
     * @throws Exception
     */
    public static List<String> obtainUnusingList(String filePath) throws Exception {
        FileInputStream fis = new FileInputStream(filePath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL aCrl = (X509CRL) cf.generateCRL(fis);

        int i = 0;
        Set tSet = aCrl.getRevokedCertificates();
        Iterator tIterator = tSet.iterator();
        //将吊销列表存入到一个列表中
        List<String> snList = new ArrayList<>();
        while (tIterator.hasNext()) {
            X509CRLEntry tEntry = (X509CRLEntry) tIterator.next();
            String sn = tEntry.getSerialNumber().toString(16).toUpperCase();
            snList.add(sn);
        }
        return snList;
    }

    /**
     * 该方法是遍历删除文件大小为0kb的文件,和以非院结尾的文件
     *
     * @param file
     * @throws Exception
     */
    private static void func(File file) throws Exception {
        File[] fs = file.listFiles();
        for (File f : fs) {
            if (f.isDirectory()) {
                func(f);
            }
            if (f.length() <= 0) {
                f.delete();
                System.out.println("删除文件成功");
            }

        }
    }

    /**
     * 删除空文件夹，方法二
     *
     * @param filePath
     */
    public static void deleteEmptyFiles(File filePath) {
        File[] dirs = filePath.listFiles();
        for (int i = 0; i < dirs.length; i++) {
            if (dirs[i].isDirectory()) {
                deleteEmptyFiles(dirs[i]);
            }
        }
        if (filePath.isDirectory() && filePath.listFiles().length <= 0 && filePath.delete()) {
            System.out.println(filePath + "清理成功");
        }
    }

    /**
     * 该方法主要的作用是删除被吊销的证书
     *
     * @param file
     * @param noUsingList
     * @throws Exception
     */
    private static void func1(File file, List<String> noUsingList) throws Exception {
        File[] fs = file.listFiles();
        for (File f : fs) {
            //若是目录，则递归查询下面的文件
            if (f.isDirectory())
                func1(f, noUsingList);
            if (f.isFile()) {
                if (getKeyUsage(f.getAbsolutePath()).endsWith("4")) {
                    f.delete();
                } else {
                    String certSn = CertSn(f.getAbsolutePath()).toUpperCase();
                    for (int i = 0; i < noUsingList.size(); i++) {
                        if (certSn.equals(noUsingList.get(i))) {
                            f.delete();
                        }
                    }
                }
            }

        }
    }

    //获取证书的序列号
    public static String CertSn(String filePath) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            // 读取证书文件
            File file = new File(filePath);
            byte[] inputBytes = FileUtil.loadFile(file);
            byte[] inStreamBytes = Base64Util.DecodeString(new String(inputBytes));
            InputStream inStream = new ByteArrayInputStream(inStreamBytes);

            // 创建X509工厂类
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            // 创建证书对象
            X509Certificate oCert = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();
            String info = null;
            info = oCert.getSerialNumber().toString(16);
            return info;
        } catch (Exception e) {
            System.out.println("请对文件路径为:( " + filePath + ")的文件进行人工证书吊销");
        }
        return "";
    }

    public static void deleteFiles(File filePath) {
        File[] dirs = filePath.listFiles();
        for (int i = 0; i < dirs.length; i++) {
            if (dirs[i].isDirectory()) {
                if (!dirs[i].getName().endsWith("院")) {
                    //递归删除所有的文件
                    deleteAllByPath(dirs[i]);
                    if (filePath.isDirectory() && filePath.listFiles().length <= 0 && filePath.delete()) {
                        System.out.println(filePath + "清理成功");
                    }
                }
            } else {
                dirs[i].delete();
            }
            if (dirs[i].isDirectory() && dirs[i].listFiles().length <= 0 && dirs[i].delete()) {
                System.out.println(filePath + "清理成功");
            }
        }
    }


    /**
     * 删除某个目录下所有文件及文件夹
     *
     * @param rootFilePath 根目录
     * @return boolean
     */
    public static boolean deleteAllByPath(File rootFilePath) {
        File[] needToDeleteFiles = rootFilePath.listFiles();
        if (needToDeleteFiles == null) {
            return true;
        }
        for (int i = 0; i < needToDeleteFiles.length; i++) {
            if (needToDeleteFiles[i].isDirectory()) {
                deleteAllByPath(needToDeleteFiles[i]);
            }
            try {
                Files.delete(needToDeleteFiles[i].toPath());
            } catch (IOException e) {
                return false;
            }
        }
        return true;
    }

    public static String getKeyUsage(String filePath) {
        String info = null;
        try {
            Security.addProvider(new BouncyCastleProvider());

            // 读取证书文件
            File file = new File(filePath);
            byte[] inputBytes = FileUtil.loadFile(file);
            byte[] inStreamBytes = Base64Util.DecodeString(new String(inputBytes));
            InputStream inStream = new ByteArrayInputStream(inStreamBytes);

            // 创建X509工厂类
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            // 创建证书对象
            X509Certificate oCert = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();
            info = oCert.getExtendedKeyUsage().get(0);
            return info;
        } catch (Exception e) {
            System.out.println("请对文件路径为:( " + filePath + ")的文件进行人工证书吊销");
        }
        return info;
    }

    public static void fileRank(File filePath) {
        File[] yuanToRankFiles = filePath.listFiles();
        if (yuanToRankFiles == null) {
            return;
        }
        for (int i = 0; i < yuanToRankFiles.length; i++) {
            File[] depentmentFile = yuanToRankFiles[i].listFiles();
            if (depentmentFile.length <= 0) {
                continue;
            }
            //新建一个存放个人证书的文件夹
            for (int j = 0; j < depentmentFile.length; j++) {
                File[] file = depentmentFile[j].listFiles();
                File newTempFilePath = null;
                if (file == null) {
                    continue;
                }
                if (depentmentFile[j].getName().contains("检察院")) {
                    //将所有的院章放入新建的文件中
                    for (int k = 0; k < file.length; k++) {
                        newTempFilePath = new File("F:\\HaveqdParseCert\\部门证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\");
                        if (!newTempFilePath.exists()) {
                            newTempFilePath.mkdirs();
                        }
                        file[k].renameTo(new File("F:\\HaveqdParseCert\\部门证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\" + file[k].getName()));
                    }
                } else {
                    for (int k = 0; k < file.length; k++) {

                        newTempFilePath = new File("F:\\HaveqdParseCert\\个人证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\");
                        if (!newTempFilePath.exists()) {
                            newTempFilePath.mkdirs();
                        }
                        file[k].renameTo(new File("F:\\HaveqdParseCert\\个人证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\" + file[k].getName()));
                    }
                }
            }
        }
    }
}

class FileUtils {
    List<File> list = new ArrayList<File>();

    // 得到某一目录下的所有文件夹
    public List<File> visitAll(File root) {
        File[] dirs = root.listFiles();
        if (dirs != null) {
            for (int i = 0; i < dirs.length; i++) {
                if (dirs[i].isDirectory()) {
                    System.out.println("name:" + dirs[i].getPath());
                    list.add(dirs[i]);
                }
                visitAll(dirs[i]);
            }
        }
        return list;
    }

    /**
     * 删除空的文件夹
     *
     * @param list
     */
    public void removeNullFile(List<File> list) {
        for (int i = 0; i < list.size(); i++) {
            File temp = list.get(i);
            // 是目录且为空
            if (temp.isDirectory() && temp.listFiles().length <= 0) {
                temp.delete();
            }
        }
    }
}


