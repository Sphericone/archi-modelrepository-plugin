/**
 * This program and the accompanying materials
 * are made available under the terms of the License
 * which accompanies this distribution in the file LICENSE.txt
 */
package org.archicontribs.modelrepository.merge;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.jface.dialogs.IMessageProvider;
import org.eclipse.jface.layout.TableColumnLayout;
import org.eclipse.jface.viewers.CellEditor;
import org.eclipse.jface.viewers.ColumnViewer;
import org.eclipse.jface.viewers.ColumnWeightData;
import org.eclipse.jface.viewers.ComboBoxCellEditor;
import org.eclipse.jface.viewers.EditingSupport;
import org.eclipse.jface.viewers.ISelectionChangedListener;
import org.eclipse.jface.viewers.IStructuredContentProvider;
import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.viewers.SelectionChangedEvent;
import org.eclipse.jface.viewers.StructuredSelection;
import org.eclipse.jface.viewers.TableViewer;
import org.eclipse.jface.viewers.TableViewerColumn;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.jface.viewers.ViewerComparator;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.custom.ScrolledComposite;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.widgets.TabItem;
import org.eclipse.swt.widgets.Text;

import com.archimatetool.editor.diagram.util.DiagramUtils;
import com.archimatetool.editor.ui.ArchiLabelProvider;
import com.archimatetool.editor.ui.IArchiImages;
import com.archimatetool.editor.ui.components.ExtendedTitleAreaDialog;
import com.archimatetool.model.IAccessRelationship;
import com.archimatetool.model.IArchimateDiagramModel;
import com.archimatetool.model.IArchimateModel;
import com.archimatetool.model.IArchimateRelationship;
import com.archimatetool.model.IDiagramModel;
import com.archimatetool.model.IDocumentable;
import com.archimatetool.model.IInfluenceRelationship;
import com.archimatetool.model.INameable;
import com.archimatetool.model.IProperties;
import com.archimatetool.model.IProperty;
import com.archimatetool.model.viewpoints.ViewpointManager;

/**
 * Conflicts Dialog
 * 
 * @author Phil Beauvoir
 */
class ConflictsDialog extends ExtendedTitleAreaDialog {
    
    private static String DIALOG_ID = "ConflictsDialog"; //$NON-NLS-1$

    // Tab Composite
    private abstract class TabComposite extends Composite {
        protected int choice;
        
        TabComposite(Composite parent, int choice) {
            super(parent, SWT.NONE);
            
            this.choice = choice;
            setBackground(parent.getDisplay().getSystemColor(SWT.COLOR_LIST_BACKGROUND));
            setBackgroundMode(SWT.INHERIT_FORCE);
            setLayout(new GridLayout());
        }
        
        abstract void setMergeInfo(MergeObjectInfo mergeInfo);
    }
    
    private MergeConflictHandler fHandler;
    
    private MergeObjectInfo currentSelectedMergeInfo;
    
    private TableViewer fTableViewer;
    
    private Button[] buttons = new Button[2];
    
    private TabFolder tabFolder;
    private TabItem itemView;
    
    private List<TabComposite> fTabComposites = new ArrayList<TabComposite>();
    
    private String[] choices = {
            "Mine",
            "Theirs"
    };
    
    ConflictsDialog(Shell parentShell, MergeConflictHandler handler) {
        super(parentShell, DIALOG_ID);
        setTitle("Merge Conflicts");
        fHandler = handler;
    }
    
    @Override
    protected void configureShell(Shell shell) {
        super.configureShell(shell);
        shell.setText("Merge Conflicts");
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        setMessage("There are conflicts between your version and the online version. Please resolve the conflicts.", IMessageProvider.WARNING);
        setTitleImage(IArchiImages.ImageFactory.getImage(IArchiImages.ECLIPSE_IMAGE_IMPORT_PREF_WIZARD));

        Composite area = (Composite) super.createDialogArea(parent);
        Composite container = new Composite(area, SWT.NONE);
        container.setLayoutData(new GridData(GridData.FILL_BOTH));
        container.setLayout(new GridLayout());
        
        SashForm sash = new SashForm(container, SWT.VERTICAL);
        sash.setLayoutData(new GridData(GridData.FILL_BOTH));
        
        createTableControl(sash);
        createTabPane(sash);
        
        sash.setWeights(new int[] { 25, 75 });
        
        // Select first object in table
        Object first = fTableViewer.getElementAt(0);
        if(first != null) {
            fTableViewer.setSelection(new StructuredSelection(first));
        }
        
        return area;
    }
    
    /**
     * Create the tab pane
     */
    private void createTabPane(Composite parent) {
        Composite mainComposite = new Composite(parent, SWT.BORDER);
        mainComposite.setLayoutData(new GridData(GridData.FILL_BOTH));
        mainComposite.setLayout(new GridLayout(2, true));
        
        tabFolder = new TabFolder(mainComposite, SWT.NONE);
        tabFolder.setLayoutData(new GridData(GridData.FILL_BOTH));
        ((GridData)tabFolder.getLayoutData()).horizontalSpan = 2;
        
        createMainTabItem();
        createPropertiesTabItem();
        // (we will create the View TabItem on demand)
        
        // Ours /Theirs buttons
        for(int i = 0; i < buttons.length; i++) {
            buttons[i] = new Button(mainComposite, SWT.PUSH);
            GridData gd = new GridData(SWT.FILL, SWT.FILL, true, false);
            buttons[i].setLayoutData(gd);
            buttons[i].setData(i);
            
            buttons[i].addSelectionListener(new SelectionAdapter() {
                @Override
                public void widgetSelected(SelectionEvent e) {
                    if(currentSelectedMergeInfo != null) {
                        currentSelectedMergeInfo.setUserChoice((int)e.widget.getData());
                        fTableViewer.update(currentSelectedMergeInfo, null);
                        updateButtons(currentSelectedMergeInfo);
                    }
                }
            });
        }
    }
    
    // =====================================
    // Main Composite
    // =====================================
    
    private TabItem createMainTabItem() {
        SashForm sash = new SashForm(tabFolder, SWT.HORIZONTAL);
        sash.setBackground(sash.getDisplay().getSystemColor(SWT.COLOR_WIDGET_BACKGROUND));
        
        fTabComposites.add(new MainComposite(sash, MergeObjectInfo.OURS));
        fTabComposites.add(new MainComposite(sash, MergeObjectInfo.THEIRS));
        
        TabItem item = new TabItem(tabFolder, SWT.NONE);
        item.setText("Main");
        item.setControl(sash);
        
        return item;
    }
    
    private class MainComposite extends TabComposite {
        private Composite fieldsComposite;
        private Label labelDocumentation;
        private Text textName, textDocumentation;
        
        private Text textSource, textTarget;
        private Text textViewpoint;
        private Text textAccessType, textInfluenceStrength;
        
        MainComposite(Composite parent, int choice) {
            super(parent, choice);
            
            fieldsComposite = new Composite(this, SWT.NONE);
            fieldsComposite.setLayoutData(new GridData(GridData.FILL_BOTH));
            fieldsComposite.setLayout(new GridLayout(2, false));

            // Name
            createLabel(fieldsComposite, "Name:", null);
            textName = createSingleText(fieldsComposite, null);
            
            // Relationship Source
            createLabel(fieldsComposite, "Source:", IArchimateRelationship.class);
            textSource = createSingleText(fieldsComposite, IArchimateRelationship.class);
            
            // Relationship Target
            createLabel(fieldsComposite, "Target:", IArchimateRelationship.class);
            textTarget = createSingleText(fieldsComposite, IArchimateRelationship.class);
            
            // Access Relationship Type
            createLabel(fieldsComposite, "Type:", IAccessRelationship.class);
            textAccessType = createSingleText(fieldsComposite, IAccessRelationship.class);

            // Influence Relationship Strength
            createLabel(fieldsComposite, "Strength:", IInfluenceRelationship.class);
            textInfluenceStrength = createSingleText(fieldsComposite, IInfluenceRelationship.class);

            // Viewpoint
            createLabel(fieldsComposite, "Viewpoint:", IArchimateDiagramModel.class);
            textViewpoint = createSingleText(fieldsComposite, IArchimateDiagramModel.class);

            // Documentation / Purpose
            labelDocumentation = new Label(fieldsComposite, SWT.NONE);
            labelDocumentation.setLayoutData(new GridData(SWT.TOP, SWT.TOP, false, false));
            textDocumentation = new Text(fieldsComposite, SWT.READ_ONLY | SWT.BORDER | SWT.MULTI | SWT.V_SCROLL | SWT.WRAP);
            textDocumentation.setLayoutData(new GridData(GridData.FILL_BOTH));
        }
        
        @Override
        void setMergeInfo(MergeObjectInfo mergeInfo) {
            EObject eObject = mergeInfo.getEObject(choice);
            
            // If object has been deleted hide fields
            fieldsComposite.setVisible(eObject != null);
            
            // Object was deleted
            if(eObject == null) {
                return;
            }
            
            // Show/Hide controls depending on object class
            for(Control control : fieldsComposite.getChildren()) {
                if(control.getData() instanceof Class) {
                    boolean isVisible = ((Class<?>)control.getData()).isInstance(eObject);
                    control.setVisible(isVisible);
                    ((GridData)control.getLayoutData()).exclude = !isVisible;
                }
            }
            
            // Name
            if(eObject instanceof INameable) {
                textName.setText(((INameable)eObject).getName());
            }
            else {
                textName.setText(""); //$NON-NLS-1$
            }

            // Relationship controls
            if(eObject instanceof IArchimateRelationship) {
                textSource.setText(((IArchimateRelationship)eObject).getSource().getName());
                textTarget.setText(((IArchimateRelationship)eObject).getTarget().getName());
                
                if(eObject instanceof IAccessRelationship) {
                    int type = ((IAccessRelationship)eObject).getAccessType();
                    if(type < IAccessRelationship.WRITE_ACCESS || type > IAccessRelationship.READ_WRITE_ACCESS) {
                        type = IAccessRelationship.WRITE_ACCESS;
                    }
                    final String[] types = { "Write", "Read", "Access", "ReadWrite" };
                    textAccessType.setText(types[type]);
                }
                else if(eObject instanceof IInfluenceRelationship) {
                    String strength = ((IInfluenceRelationship)eObject).getStrength();
                    textInfluenceStrength.setText(strength);
                }
            }

            // Documentation / Purpose
            if(eObject instanceof IDocumentable) {
                labelDocumentation.setText("Documentation:");
                textDocumentation.setText(((IDocumentable)eObject).getDocumentation());
            }
            else if(eObject instanceof IArchimateModel) {
                labelDocumentation.setText("Purpose:");
                textDocumentation.setText(((IArchimateModel)eObject).getPurpose());
            }
            else {
                textDocumentation.setText(""); //$NON-NLS-1$
            }
            
            // Viewpoint
            if(eObject instanceof IArchimateDiagramModel) {
                String name = ViewpointManager.INSTANCE.getViewpoint(((IArchimateDiagramModel)eObject).getViewpoint()).getName();
                textViewpoint.setText(name);
            }
            
            fieldsComposite.layout();
        }
    }
    
    private Label createLabel(Composite parent, String text, Class<?> c) {
        Label label = new Label(parent, SWT.NONE);
        label.setText(text);
        label.setLayoutData(new GridData());
        label.setData(c);
        return label;
    }
    
    private Text createSingleText(Composite parent, Class<?> c) {
        Text text = new Text(parent, SWT.READ_ONLY | SWT.BORDER);
        text.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        text.setData(c);
        return text;
    }

    // =====================================
    // Properties Composite
    // =====================================
    
    private TabItem createPropertiesTabItem() {
        SashForm sash = new SashForm(tabFolder, SWT.HORIZONTAL);
        sash.setBackground(sash.getDisplay().getSystemColor(SWT.COLOR_WIDGET_BACKGROUND));
        
        fTabComposites.add(new PropertiesComposite(sash, MergeObjectInfo.OURS));
        fTabComposites.add(new PropertiesComposite(sash, MergeObjectInfo.THEIRS));
        
        TabItem item = new TabItem(tabFolder, SWT.NONE);
        item.setText("Properties");
        item.setControl(sash);
        
        return item;
    }
    
    private class PropertiesComposite extends TabComposite {
        private TableViewer propertiesTableViewer;

        PropertiesComposite(Composite parent, int choice) {
            super(parent, choice);
            
            Composite tableComp = new Composite(this, SWT.BORDER);
            TableColumnLayout tableLayout = new TableColumnLayout();
            tableComp.setLayout(tableLayout);
            tableComp.setLayoutData(new GridData(GridData.FILL_BOTH));

            propertiesTableViewer = new TableViewer(tableComp, SWT.MULTI | SWT.FULL_SELECTION);
            propertiesTableViewer.getTable().setHeaderVisible(true);
            propertiesTableViewer.getTable().setLinesVisible(true);
            propertiesTableViewer.setComparator(new ViewerComparator());
            
            TableViewerColumn columnKey = new TableViewerColumn(propertiesTableViewer, SWT.NONE, 0);
            columnKey.getColumn().setText("Name");
            tableLayout.setColumnData(columnKey.getColumn(), new ColumnWeightData(25, true));

            TableViewerColumn columnValue = new TableViewerColumn(propertiesTableViewer, SWT.NONE, 1);
            columnValue.getColumn().setText("Value");
            tableLayout.setColumnData(columnValue.getColumn(), new ColumnWeightData(75, true));

            // Properties Table Content Provider
            propertiesTableViewer.setContentProvider(new IStructuredContentProvider() {
                public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
                }

                public void dispose() {
                }

                public Object[] getElements(Object inputElement) {
                    if(inputElement instanceof IProperties) {
                        return ((IProperties)inputElement).getProperties().toArray();
                    }
                    return new Object[0];
                }
            });

            // Properties Table Label Provider
            class PropertiesLabelCellProvider extends LabelProvider implements ITableLabelProvider {
                public Image getColumnImage(Object element, int columnIndex) {
                    return null;
                }

                @Override
                public String getColumnText(Object element, int columnIndex) {
                    switch(columnIndex) {
                        case 0:
                            return ((IProperty)element).getKey();

                        case 1:
                            return ((IProperty)element).getValue();

                        default:
                            return null;
                    }
                }
            }

            propertiesTableViewer.setLabelProvider(new PropertiesLabelCellProvider());
        }

        @Override
        void setMergeInfo(MergeObjectInfo mergeInfo) {
            EObject eObject = mergeInfo.getEObject(choice);
            
            // If object has been deleted hide fields
            propertiesTableViewer.getControl().setVisible(eObject != null);
            
            // Properties
            if(eObject instanceof IProperties) {
                propertiesTableViewer.setInput(eObject);
            }
            else {
                propertiesTableViewer.setInput(""); //$NON-NLS-1$
            }
        }
    }
    
    // =====================================
    // View Composite
    // =====================================
    
    private TabItem createViewTabItem() {
        SashForm sash = new SashForm(tabFolder, SWT.HORIZONTAL);
        sash.setBackground(sash.getDisplay().getSystemColor(SWT.COLOR_WIDGET_BACKGROUND));
        
        ViewComposite c1 = new ViewComposite(sash, MergeObjectInfo.OURS);
        fTabComposites.add(c1);
        ViewComposite c2 = new ViewComposite(sash, MergeObjectInfo.THEIRS);
        fTabComposites.add(c2);
        
        TabItem item = new TabItem(tabFolder, SWT.NONE);
        item.setText("View");
        item.setControl(sash);
        
        // TabItem child controls are not disposed when a TabItem is disposed
        item.addDisposeListener((event) -> {
            // Remove composites from the update list
            fTabComposites.remove(c1);
            fTabComposites.remove(c2);
            sash.dispose(); // Dispose of top parent, will cause dispose of children and image
        });
        
        return item;
    }
    
    private class ViewComposite extends TabComposite {
        private Image viewImage;
        private Label viewLabel;
        
        ViewComposite(Composite parent, int choice) {
            super(parent, choice);
            
            // Dispose of image when done
            parent.addDisposeListener((e) -> {
                disposeImage();
            });

            ScrolledComposite scImage = new ScrolledComposite(this, SWT.H_SCROLL | SWT.V_SCROLL );
            scImage.setLayoutData(new GridData(GridData.FILL_BOTH));
            viewLabel = new Label(scImage, SWT.NONE);
            scImage.setContent(viewLabel);
        }

        @Override
        void setMergeInfo(MergeObjectInfo mergeInfo) {
            disposeImage();
            viewLabel.setImage(null);
            
            EObject eObject = mergeInfo.getEObject(choice);
            
            // Object was deleted
            if(eObject == null) {
                return;
            }
            
            // View
            if(eObject instanceof IDiagramModel) {
                viewImage = DiagramUtils.createImage((IDiagramModel)eObject, 1, 5);
                viewLabel.setImage(viewImage);
            }
            
            viewLabel.setSize(viewLabel.computeSize( SWT.DEFAULT, SWT.DEFAULT));
        }
        
        void disposeImage() {
            if(viewImage != null && !viewImage.isDisposed()) {
                viewImage.dispose();
                viewImage = null;
            }
        }
    }

    // =====================================
    // Other
    // =====================================
    
    private void updateTabs(MergeObjectInfo mergeInfo) {
        if(currentSelectedMergeInfo == mergeInfo) {
            return;
        }
        
        currentSelectedMergeInfo = mergeInfo;
        
        updateButtons(mergeInfo);
        
        // If the eObject is a View add the View TabItem, else remove it
        EObject eObject = mergeInfo.getDefaultEObject();
        if(eObject instanceof IDiagramModel) {
            if(itemView == null) {
                itemView = createViewTabItem();
            }
        }
        else if(itemView != null && !itemView.isDisposed()) {
            itemView.dispose();
            itemView = null;
        }
        
        // Update tab composites
        for(TabComposite c : fTabComposites) {
            c.setMergeInfo(mergeInfo);
        }
    }

    private void updateButtons(MergeObjectInfo mergeInfo) {
        int choice = mergeInfo.getUserChoice();
        for(int i = 0; i < buttons.length; i++) {
            buttons[i].setText(choices[i] + (choice == i ? " (selected)" : ""));
        }
    }
    
    @Override
    protected Point getDefaultDialogSize() {
        return new Point(700, 550);
    }
    
    @Override
    protected boolean isResizable() {
        return true;
    }

    // ===========================================================
    // Top Table Control
    // ===========================================================
    
    private void createTableControl(Composite parent) {
        Composite tableComp = new Composite(parent, SWT.BORDER);
        TableColumnLayout tableLayout = new TableColumnLayout();
        tableComp.setLayout(tableLayout);
        tableComp.setLayoutData(new GridData(GridData.FILL_BOTH));

        fTableViewer = new TableViewer(tableComp, SWT.FULL_SELECTION);
        fTableViewer.getControl().setLayoutData(new GridData(GridData.FILL_BOTH));
        fTableViewer.getTable().setHeaderVisible(true);
        fTableViewer.getTable().setLinesVisible(true);
        fTableViewer.setComparator(new ViewerComparator() {
            @Override
            public int compare(Viewer viewer, Object object1, Object object2) {
                EObject eObject1 = ((MergeObjectInfo)object1).getDefaultEObject();
                EObject eObject2 = ((MergeObjectInfo)object2).getDefaultEObject();
                String s1 = ArchiLabelProvider.INSTANCE.getDefaultName(eObject1.eClass());
                String s2 = ArchiLabelProvider.INSTANCE.getDefaultName(eObject2.eClass());
                return s1.compareToIgnoreCase(s2);
            }
        });

        // Columns
        TableViewerColumn column1 = new TableViewerColumn(fTableViewer, SWT.NONE, 0);
        column1.getColumn().setText("Type");
        tableLayout.setColumnData(column1.getColumn(), new ColumnWeightData(30, true));

        TableViewerColumn column2 = new TableViewerColumn(fTableViewer, SWT.NONE, 1);
        column2.getColumn().setText("Name");
        tableLayout.setColumnData(column2.getColumn(), new ColumnWeightData(40, true));

        TableViewerColumn column3 = new TableViewerColumn(fTableViewer, SWT.NONE, 2);
        column3.getColumn().setText("Status");
        tableLayout.setColumnData(column3.getColumn(), new ColumnWeightData(15, true));

        TableViewerColumn column4 = new TableViewerColumn(fTableViewer, SWT.NONE, 3);
        column4.getColumn().setText("Choice");
        tableLayout.setColumnData(column4.getColumn(), new ColumnWeightData(15, true));
        column4.setEditingSupport(new ComboChoiceEditingSupport(fTableViewer));

        // Content Provider
        fTableViewer.setContentProvider(new IStructuredContentProvider() {
            public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
            }

            public void dispose() {
            }

            public Object[] getElements(Object inputElement) {
                return fHandler.getMergeObjectInfos().toArray();
            }
        });

        // Table Selection Listener
        fTableViewer.addSelectionChangedListener(new ISelectionChangedListener() {
            @Override
            public void selectionChanged(SelectionChangedEvent event) {
                MergeObjectInfo info = (MergeObjectInfo)((StructuredSelection)event.getSelection()).getFirstElement();
                updateTabs(info);
            }
        });
        
        // Table Label Provider
        fTableViewer.setLabelProvider(new TableLabelProvider());
        
        // Start the table
        fTableViewer.setInput(""); // anything will do //$NON-NLS-1$
    }
    // Label Provider
    private class TableLabelProvider extends LabelProvider implements ITableLabelProvider {
        
        public Image getColumnImage(Object element, int columnIndex) {
            if(columnIndex == 0) {
                MergeObjectInfo info = (MergeObjectInfo)element;
                return ArchiLabelProvider.INSTANCE.getImage(info.getDefaultEObject());
            }
            
            return null;
        }

        public String getColumnText(Object element, int columnIndex) {
            MergeObjectInfo info = (MergeObjectInfo)element;
            EObject eObject = info.getDefaultEObject();
            
            if(eObject == null) {
                return "(missing)";
            }
            
            switch(columnIndex) {
                case 0:
                    return ArchiLabelProvider.INSTANCE.getDefaultName(eObject.eClass());

                case 1:
                    return ArchiLabelProvider.INSTANCE.getLabel(eObject);

                case 2:
                    return info.getStatus();

                case 3:
                    return choices[info.getUserChoice()];

                default:
                    return ""; //$NON-NLS-1$
            }
        }
    }

    /**
     * Combo Choice Editor
     */
    private class ComboChoiceEditingSupport extends EditingSupport {
        private ComboBoxCellEditor cellEditor;
        
        public ComboChoiceEditingSupport(ColumnViewer viewer) {
            super(viewer);
            cellEditor = new ComboBoxCellEditor((Composite)viewer.getControl(), choices, SWT.READ_ONLY);
        }

        @Override
        protected CellEditor getCellEditor(Object element) {
            return cellEditor;
        }

        @Override
        protected boolean canEdit(Object element) {
            return true;
        }

        @Override
        protected Object getValue(Object element) {
            MergeObjectInfo info = (MergeObjectInfo)element;
            return info.getUserChoice();
        }

        @Override
        protected void setValue(Object element, Object value) {
            MergeObjectInfo info = (MergeObjectInfo)element;
            info.setUserChoice((int)value);
            fTableViewer.update(element, null);
            updateButtons(info);
        }
    }

}
