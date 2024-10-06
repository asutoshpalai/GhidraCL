/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidracl;

import java.awt.BorderLayout;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.*;

import org.apache.commons.io.FileUtils;
import org.armedbear.lisp.Interpreter;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidra Common Lisp",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Common Lisp for Ghidra.",
	description = "Common Lisp for Ghidra."
)
//@formatter:on
public class GhidraCLPlugin extends ProgramPlugin {

	MyProvider provider;
	
    private DockingAction startSlynkAction;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraCLPlugin(PluginTool tool) {
		super(tool);

		/*// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));*/
		
		
	}

	@Override
	public void init() {
		super.init();
		
		tool.execute(new Task("create ABCL instance") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
						Interpreter.createDefaultInstance(null); 
			}
		});

		setupActions();
		
	}
	
	private void setupActions() {
        DockingAction action;

        // add menu action for Hello->Program
        action = new DockingAction("Start Slynk", getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                startSlynk();
            }
        };
        //action.setEnabled( getProgram() != null );    
        action.setEnabled(true);
        action.setMenuBarData( new MenuData( new String[]{"Common Lisp","Start Slynk"}, "Slynk" ) );
        tool.addAction(action);
        
        action = new DockingAction("Load Quicklisp", getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                installQuicklisp();
            }
        };
        //action.setEnabled( getProgram() != null );    
        action.setEnabled(true);
        action.setMenuBarData( new MenuData( new String[]{"Common Lisp","Load Quicklisp"}, "Quicklisp" ) );
        tool.addAction(action);

        // remember this action so I can enable/disable it later
       // startSlynkAction = action;
        
        
    }
	
	protected void installQuicklisp() {
		Path quicklispSetup = Paths.get(System.getProperty("user.home")).
				resolve("quicklisp").
				resolve("setup.lisp");
		
		if (!Files.exists(quicklispSetup)) {
			Msg.info(GhidraCLPlugin.class, "installing quicklisp");
			
			// TODO: Move them to tool.execute since they are non cancellable and don't have progress bar
			TaskLauncher.launchModal("Installing Quicklisp", monitor -> {
				URL quicklispURL;
				try {
					quicklispURL = new URI("https://beta.quicklisp.org/quicklisp.lisp").toURL();
					Path tempDir = Files.createTempDirectory("ghidra-cl-quicklisp");
					Path quicklispFile = tempDir.resolve("quicklisp.lisp");
					FileUtils.copyURLToFile(quicklispURL, quicklispFile.toFile());
					
					Msg.info(GhidraCLPlugin.class, String.format("quicklisp setup downloaded: %s", quicklispFile));
					// TODO: download the signature of the quicklisp file and verify it too
					
					Interpreter.evaluate(String.format("(load \"%s\")",  quicklispFile.toString()));
					Interpreter.evaluate("(quicklisp-quickstart:install)");
					Msg.info(GhidraCLPlugin.class, "quicklisp installed");
				} catch (Exception e) {
					Msg.showError(GhidraCLPlugin.class, null, "Installing Quicklisp", "failed to install quicklisp", e);
				}
	    	});
		}
		
		TaskLauncher.launchModal("Loading Quicklisp", monitor -> {
	    	Interpreter.evaluate("(load \"~/quicklisp/setup.lisp\")");
		});
    	Msg.showInfo(GhidraCLPlugin.class, null, "Load Quicklisp", "Quicklisp loaded");
    }
	
	
    /**
     * Callback for Hello->Program menu option
     */
    protected void startSlynk() {
    	TaskLauncher.launchModal("Starting Slynk", monitor -> {
    		Interpreter.evaluate("(ql:quickload \"slynk\")");
    		Interpreter.evaluate("(slynk:create-server :port 4008)");
    	});
    	
    	Msg.showInfo(GhidraCLPlugin.class, null, "Start Slynk", "Slynk started at localhost:4008");
 
    }

    protected void announce(String message) {
        JOptionPane.showMessageDialog(null,message,"Hello World",
                                      JOptionPane.INFORMATION_MESSAGE);
    }


    /**
     * Get the currently open program using the ProgramManager service.
     */
    private Program getProgram() {

		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			return pm.getCurrentProgram();
		}
		return null;
    }

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
