/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.csdaemon;

import com.aaasec.sigserv.cssigapp.instances.InstanceMetadataFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author stefan
 */
public class CaDaemon {

    private static final Logger LOG = Logger.getLogger(CaDaemon.class.getName());
    CaDaemonOperations daemonTask;
    DaemonModel model;
    private long daemonCycle = 720000;
    boolean taskInAction;
    boolean stop;
    InstanceMetadataFactory instMdFact;

    public CaDaemon() {
        this.model = new DaemonModel();
        this.daemonTask = new CaDaemonOperations(model);
        this.instMdFact = new InstanceMetadataFactory(ContextParameters.getInstanceConf());
    }

    void invokeDaemon() {
        stop = false;
        Thread thread = new Thread(new CacheTimer(daemonCycle));
        thread.setDaemon(true);
        thread.start();
    }

    void stopDaemon() {
        stop = true;
    }

    private boolean running(Thread thread) {
        return (thread != null && thread.isAlive());
    }

    class CacheTimer implements Runnable {

        long cycleTime;

        public CacheTimer(long time) {
            this.cycleTime = time;
        }

        @Override
        public void run() {
            long nextUpdate = 0;
            while (!stop) {

                if (System.currentTimeMillis() > nextUpdate) {
                    nextUpdate = System.currentTimeMillis() + cycleTime;
                    LOG.info("Start Sign service Instance Metadata Publication ...");
                    try {
                        instMdFact.storeInstanceMetadata();
                    }
                    catch (Exception e) {
                        LOG.warning("Error encountered while attempting to sign instance metadata: " + e.getMessage());
                        LOG.log(Level.FINE, "Detailed error trace - signature error", e);
                    }
                    LOG.info("Start Sign service daemon process ...");
                    try {
                        daemonTask.doDaemonTask();
                    } catch (Exception ex) {
                        LOG.warning("Exception caught while performing daemontask: " + ex.getMessage());
                        LOG.log(Level.FINE, "Detailed error trace: " + ex.getMessage(), ex);
                    }
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    LOG.log(Level.WARNING, ex.getLocalizedMessage());
                }
            }
        }
    }
}
