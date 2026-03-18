package ra_practice.project_2;


public class VigenereCipher {
    private static final String KEY = "TMU";

    public static String encrypt(String text) {
        return vigenere(text, true);
    }

    public static String decrypt(String text) {
        return vigenere(text, false);
    }

    private static String vigenere(String text, boolean encrypt) {
        StringBuilder out = new StringBuilder();
        int j = 0;

        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                boolean lower = Character.isLowerCase(c);
                int p = Character.toUpperCase(c) - 'A';
                int k = KEY.charAt(j % KEY.length()) - 'A';

                int r = encrypt ? (p + k) % 26 : (p - k + 26) % 26;
                out.append((char) ((lower ? 'a' : 'A') + r));

                j++;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
