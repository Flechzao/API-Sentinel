package com.flechazo.apisentinel.ui;

import javax.swing.*;
import java.awt.*;

public class TaskQueueDialog extends JDialog {

    public TaskQueueDialog(Window owner, TaskQueuePanel taskQueuePanel) {
        super(owner, I18n.get("tab_task_center"), ModalityType.MODELESS);
        setDefaultCloseOperation(HIDE_ON_CLOSE);
        setSize(700, 450);
        setMinimumSize(new Dimension(500, 300));
        setLocationRelativeTo(owner);
        getContentPane().add(taskQueuePanel, BorderLayout.CENTER);
        // ESC hides — matches every other dialog's dismissal convention.
        getRootPane().registerKeyboardAction(e -> setVisible(false),
                KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
    }
}
