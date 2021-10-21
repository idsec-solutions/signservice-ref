package com.aaasec.sigserv.cssigapp.instances;

/**
 *
 * @author stefan
 */
public class MetadataLogo {

    private final String height;
    private final String width;
    private final String logoFileName;

    public MetadataLogo(String height, String width, String logoFileName) {
        this.height = height;
        this.width = width;
        this.logoFileName = logoFileName;
    }

    public String getHeight() {
        return height;
    }

    public String getWidth() {
        return width;
    }

    public String getLogoFileName() {
        return logoFileName;
    }
}
