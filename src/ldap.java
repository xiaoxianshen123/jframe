import com.sdt.util.file.FileUtil;
import com.sdt.util.security.Base64Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

import static java.util.Base64.getDecoder;

public class ldap {

    public static void main(String[] args) throws Exception {
        // 创建 JFrame 实例
        JFrame frame = new JFrame("解析证书文件");
        frame.setSize(450, 700);
        frame.setLocation(400, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        JPanel panel = new JPanel();
        createPanel(panel);
        frame.add(panel);
    }

    private static void createPanel(JPanel panel) throws Exception{
        panel.setLayout(null);
        JLabel ldif = new JLabel();
        ldif.setText("请上传ldif文件");
        ldif.setBounds(10, 10, 200, 15);
        panel.add(ldif);
        //增加上传文件的框
        final JTextField textField = new JTextField();
        textField.setBounds(10, 35, 300, 20);
        panel.add(textField);
        //增加浏览按钮
        final JButton browser = createButton();
        browser.setBounds(320, 35, 80, 20);
        ;
        panel.add(browser);

        //增加上传文件label
        JLabel crt = new JLabel();
        crt.setText("请上传crt文件");
        crt.setBounds(10, 65, 200, 15);
        panel.add(crt);
        //增加上传文件的框
        final JTextField textField1 = new JTextField();
        final String[] ldifFilePath = {""};
        final String[] crtFilePath = {""};
        textField1.setBounds(10, 90, 300, 20);
        panel.add(textField1);
        //增加浏览按钮
        JButton browser1 = createButton();
        browser1.setBounds(320, 90, 80, 20);
        panel.add(browser1);

        //增加文本框
        JTextArea text = createTextfiled();
        panel.add(text);

        //增加开始解析文件的按钮
        final JButton parse = createButton();
        parse.setBounds(140, 120, 140, 30);
        parse.setText("开始解析文件");
        panel.add(parse);
        parse.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(ldifFilePath.length>0 &&crtFilePath.length>0){
                    try {
                        text.append("开始。。。。。");
                        parseFile(ldifFilePath[0],crtFilePath[0],text);
                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }
                }
            }
        });
        browser.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                chooser.setMultiSelectionEnabled(true);
                FileNameExtensionFilter filter = new FileNameExtensionFilter("ldif", "xml", "txt", "doc", "docx");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(browser);
                chooser.getCurrentDirectory().getPath();
                System.out.println("文件路径是：");
                System.out.println(chooser.getCurrentDirectory().getPath());
                System.out.println("文件名是：");
                System.out.println(chooser.getSelectedFile().getName());
                String browserFile=chooser.getCurrentDirectory().getPath() + File.separator + chooser.getSelectedFile().getName();
                textField.setText(browserFile);
                text.append(browserFile+ "\n");
                ldifFilePath[0] =browserFile;
            }
        });
        browser1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                chooser.setMultiSelectionEnabled(true);
                FileNameExtensionFilter filter = new FileNameExtensionFilter("crt", "xml", "txt", "doc", "docx");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(browser);
                chooser.getCurrentDirectory().getPath();
                System.out.println("文件路径是：");
                System.out.println(chooser.getCurrentDirectory().getPath());
                System.out.println("文件名是：");
                System.out.println(chooser.getSelectedFile().getName());
                String browserFile=chooser.getCurrentDirectory().getPath() + File.separator + chooser.getSelectedFile().getName();
                textField1.setText(browserFile);
                text.append(browserFile + "\n");
                 crtFilePath[0] =browserFile;
            }
        });
    }

    private static JButton createButton() {
        JButton button = new JButton();
        button.setText("浏览");
        return button;
    }

    private static JTextArea createTextfiled() {
        JTextArea textField = new JTextArea();
        textField.setBounds(10, 170, 400, 430);
        return textField;
    }

    private static void parseFile(String ldifFilePath, String crtFilePath,JTextArea text)throws Exception {
        System.out.println("mian:"+ldifFilePath);
        System.out.println("mian:"+crtFilePath);

        String desFilePath = "D:/证书文件集/";
        ldifFilePath = ldifFilePath.replace("\\", "\\\\");
        crtFilePath=crtFilePath.replace("\\", "\\\\");
        text.append("第一步解析ldap文件" + "\n");
        text.append("解析ldap文件中........请耐心等待!!!" + "\n");
        spliteLdifFile(ldifFilePath, desFilePath);
        text.append("第二步删除吊销证书" + "\n");
        File file = new File(desFilePath);        //获取其file对象
        func(file, obtainUnusingList(crtFilePath));
        text.append("第三步删除非院的文件夹内容......" + "\n");
        File fileEmpty = new File(desFilePath);
        deleteFiles(fileEmpty);
        fileRank(fileEmpty);
        deleteEmptyFiles(fileEmpty);
        text.append("D:/证书文件集/目录下查看证书文件" + "\n");
    }

    private static void spliteLdifFile(String ldifFilePath, String desFilePath) {
        final Base64.Decoder decoder = getDecoder();
        final Base64.Encoder encoder = Base64.getEncoder();
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
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
     * 该方法主要的作用是删除被吊销的证书
     *
     * @param file
     * @param noUsingList
     * @throws Exception
     */
    private static void func(File file, List<String> noUsingList) throws Exception {
        File[] fs = file.listFiles();
        for (File f : fs) {
            //若是目录，则递归查询下面的文件
            if (f.isDirectory())
                func(f, noUsingList);
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
                        newTempFilePath = new File("D:\\证书文件集\\部门证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\");
                        if (!newTempFilePath.exists()) {
                            newTempFilePath.mkdirs();
                        }
                        file[k].renameTo(new File("D:\\证书文件集\\部门证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\" + file[k].getName()));
                    }
                } else {
                    for (int k = 0; k < file.length; k++) {

                        newTempFilePath = new File("D:\\证书文件集\\个人证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\");
                        if (!newTempFilePath.exists()) {
                            newTempFilePath.mkdirs();
                        }
                        file[k].renameTo(new File("D:\\证书文件集\\个人证书\\" + yuanToRankFiles[i].getName() + "\\" + depentmentFile[j].getName() + "\\" + file[k].getName()));
                    }
                }
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
}


