/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.csdaemon.html;

import java.util.List;

/**
 * Table element
 */
public class TableElement extends HtmlElement {

    public TableElement() {
        this("", "");
    }

    public TableElement(String className) {
        this(className, "");
    }

    public TableElement(String className, String id) {
        this.tag = "table";
        if (className.length() > 0) {
            this.addAttribute("class", className);
        }
        if (id.length() > 0) {
            this.addAttribute("id", id);
        }
    }

    public void addRow(String[] cells, String[] classNames, int colspan, boolean[] show) {
        String trClass = classNames.length > 0 ? classNames[0] : "";
        TableRowElement tr = new TableRowElement(trClass);

        int maxTdClass = classNames.length - 1;

        for (int i = 0; i < cells.length; i++) {
            String cell = cells[i];
            int cs = (i == cells.length - 1) ? colspan : 1;
            String cls = (i < maxTdClass) ? classNames[i + 1] : "";
            TableCellElement td = new TableCellElement(cell, cs, cls);
            try {
                if (!show[i]) {
                    td.addStyle("display", "none");
                }
            } catch (Exception ex) {
            }
            tr.addHtmlElement(td);
        }
        addHtmlElement(tr);
    }

    public void addRow(String[] cells, String className, int colspan, boolean[] show) {
        addRow(cells, new String[]{className}, colspan, show);
    }

    public void addRow(String[] cells, String className) {
        addRow(cells, new String[]{className}, 1, new boolean[]{true});
    }

    public void addRow(String cell, String[] classNames, int colspan, boolean show) {
        addRow(new String[]{cell}, classNames, colspan, new boolean[]{show});
    }

    public void addRow(String cell, String className, int colspan, boolean show) {
        addRow(new String[]{cell}, new String[]{className}, colspan, new boolean[]{show});
    }

    public void addRow(String cell, String className) {
        addRow(new String[]{cell}, new String[]{className}, 1, new boolean[]{true});
    }

    public void addRow(String[] cells, int colspan) {
        addRow(cells, "", colspan, new boolean[]{true});
    }

    public void addRow(String[] cells, String[] classNames, boolean[] show) {
        addRow(cells, classNames, 1, show);
    }

    public void addRow(String[] cells) {
        addRow(cells, 1);
    }

    public void addRow(String cell, int colspan) {
        addRow(new String[]{cell}, colspan);
    }

    public void addRow(String cell) {
        addRow(new String[]{cell}, 1);
    }

    public TableRowElement getLastTableRow() {
        TableRowElement tr;
        List<HtmlElement> elements = getElements();
        if (elements.isEmpty()) {
            tr = new TableRowElement();
            addHtmlElement(tr);
            return tr;
        }
        HtmlElement he = elements.get(elements.size() - 1);
        if (he instanceof TableRowElement) {
            tr = (TableRowElement) he;
        } else {
            tr = new TableRowElement();
            addHtmlElement(tr);
        }
        return tr;
    }
}
