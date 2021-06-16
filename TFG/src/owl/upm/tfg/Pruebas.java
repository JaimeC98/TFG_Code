package owl.upm.tfg;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Locale;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.jena.graph.Node;
import org.apache.jena.ontology.*;
import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.util.iterator.ExtendedIterator;
import org.topbraid.spin.util.JenaUtil;

public class Pruebas {

public static void main (String args[]) throws FileNotFoundException, ParseException {
	Model n = RDFDataMgr.loadModel("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\TFG_base.owl");
	OntModel ontModel = JenaUtil.createOntologyModel(OntModelSpec.OWL_MEM,n); //se carga el archivo en un ontModel
	
	SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
	
	String uri = "http://www.semanticweb.org/tfg/Ontologia_TFG#";
	String uri2 = "http://www.co-ode.org/ontologies/ont.owl#";
    int noIndividuos = 3;
    String prob [] = {"3.0", "7.0", "5.0"}; //probabilidades e impactos de amenazas por anomalias
    String impa [] = {"8.0", "5.0", "6.0"};
    String probV [] = {"4.0", "5.0", "3.0", "4.0", "6.0", "5.0", "4.0"}; //probabilidades e impactos de amenazas por vulnerabilidades
    String impaV [] = {"7.0", "6.0", "4.0", "5.0", "5.0", "3.0", "5.0"};
    String probA [] = {"5.0", "6.0", "7.0", "6.0", "2.0", "2.0", "2.0", "2.0"}; //probabilidades e impactos de amenazas por vulnerabilidades
    String impaA [] = {"4.0", "1.0", "5.0", "2.0", "3.0", "3.0", "3.0", "3.0"};
    String classN [] = {"FW_", "BT_", "WF_"};
    
    //Anomalias
    OntClass clAnom1 = ontModel.getOntClass(uri + "Firewall_Anomaly");
    OntClass clAnom2 = ontModel.getOntClass(uri + "Bluetooth_Sensor_Anomaly");
    OntClass clAnom3 = ontModel.getOntClass(uri + "WiFi_Sensor_Anomaly");
    OntClass anCl [] = {clAnom1, clAnom2, clAnom3};
    Date fecha1 = dateFormat.parse("2021-05-01");
    Date fecha2 = new Date();
    
    //Amenazas
    OntClass clTh1 = ontModel.getOntClass(uri + "DeliberatedUnauthorizedAccess");
    OntClass clTh2 = ontModel.getOntClass(uri + "DenialOfService");
    OntClass clTh3 = ontModel.getOntClass(uri + "ConfigurationError");
    OntClass thCl [] = {clTh1, clTh2, clTh3};
    
    //Vulnerabilidad
    Individual r1 = ontModel.getIndividual(uri + "R1");
    Individual r2 = ontModel.getIndividual(uri + "R2");
    Individual r3 = ontModel.getIndividual(uri + "R3");
    Individual pc1 = ontModel.getIndividual(uri + "PC1");
    Individual pc2 = ontModel.getIndividual(uri + "PC2");
    Individual pc3 = ontModel.getIndividual(uri + "PC3");
    Individual pc4 = ontModel.getIndividual(uri + "PC4");
    OntClass clVulThRouter = ontModel.getOntClass(uri + "NetworkOutage"); //amenaza de routers
    String diminR1 = "NO_1";
    String diminR2 = "NO_2";
    String diminR3 = "NO_3";
    OntClass clVulThPC14 = ontModel.getOntClass(uri + "DenialOfService"); //amenaza de PC1 Y PC4
    String diminPC1 = "DS_1";
    String diminPC4 = "DS_2";
    OntClass clVulThPC2 = ontModel.getOntClass(uri + "SWVulnerabilities"); //amenaza de PC2
    String diminPC2 = "SWV_1";
    OntClass clVulThPC3 = ontModel.getOntClass(uri + "MonitoringError"); //amenaza de PC3
    String diminPC3 = "ME_1";

    //AssetThreats
    OntClass clAsTh1 = ontModel.getOntClass(uri + "DeviceTheft"); //amenaza de robo que afecta a todos los ordenadores y un movil
    String dimin1 = "DT_1";
    String dimin2 = "DT_2";
    String dimin3 = "DT_3";
    String dimin4 = "DT_4";
    String dimin5 = "DT_5";
    Individual m1 = ontModel.getIndividual(uri + "M1");
    OntClass clAsTh2 = ontModel.getOntClass(uri + "DeviceLost"); //amenaza de perdida que afecta a dos ordenadores y un movil
    String diminl1 = "DL_1";
    String diminl2 = "DL_2";
    String diminl3 = "DL_3";
    Individual m2 = ontModel.getIndividual(uri + "M2");
    OntClass clAsThIt = ontModel.getOntClass(uri + "IdentityThief"); //amenaza de robo de identidad que afecta a un usuario
    String dimint1 = "IT_1";
    Individual u1 = ontModel.getIndividual(uri + "U1");
    OntClass clAsThNon = ontModel.getOntClass(uri + "NonIntentionalUserError"); //amenaza erro no intencional de un usuario
    String diminn1 = "NUE_1";
    Individual u2 = ontModel.getIndividual(uri + "U2");
    OntClass clAsThUs = ontModel.getOntClass(uri + "UsersComplaints"); //amenaza de problemas de un usuario
    String diminu1 = "UC_1";
    Individual u3 = ontModel.getIndividual(uri + "U3");
    OntClass clAsThSo = ontModel.getOntClass(uri + "SocialEngineering"); //amenaza de ingenieria social a un usuario
    String dimins1 = "SE_1";
    Individual u4 = ontModel.getIndividual(uri + "U4");
 
    
    //Comienza
    MetodosInicio inicio = new MetodosInicio();
    MetodosEliminacion eliminacion = new MetodosEliminacion();
   
    //inicio.totalRisk(ontModel);
 
     
    inicio.relationVul(uri, uri2, ontModel);
    
    inicio.genVul(r1, clVulThRouter, diminR1, probV[0], impaV[0], uri, uri2, ontModel);
    inicio.genVul(r2, clVulThRouter, diminR2, probV[1], impaV[1], uri, uri2, ontModel);
    inicio.genVul(r3, clVulThRouter, diminR3, probV[2], impaV[2], uri, uri2, ontModel);
    inicio.genVul(pc1, clVulThPC14, diminPC1, probV[3], impaV[3], uri, uri2, ontModel);
    inicio.genVul(pc2, clVulThPC2, diminPC2, probV[4], impaV[4], uri, uri2, ontModel);
    inicio.genVul(pc3, clVulThPC3, diminPC3, probV[5], impaV[5], uri, uri2, ontModel);
    inicio.genVul(pc4, clVulThPC14, diminPC4, probV[6], impaV[6], uri, uri2, ontModel);
    
    //inicio.genRs(ontModel, uri);   
 
    inicio.genAssetTh(pc1, clAsTh1, dimin1, probA[0], impaA[0], uri, ontModel);
    inicio.genAssetTh(pc2, clAsTh1, dimin2, probA[0], impaA[0], uri, ontModel);
    inicio.genAssetTh(pc3, clAsTh1, dimin3, probA[0], impaA[0], uri, ontModel);
    inicio.genAssetTh(pc4, clAsTh1, dimin4, probA[0], impaA[0], uri, ontModel);
    inicio.genAssetTh(pc1, clAsTh2, diminl1, probA[1], impaA[1], uri, ontModel);
    inicio.genAssetTh(pc4, clAsTh2, diminl2, probA[1], impaA[1], uri, ontModel);
    inicio.genAssetTh(m1, clAsTh1, dimin5, probA[2], impaA[2], uri, ontModel);
    inicio.genAssetTh(m2, clAsTh2, diminl3, probA[3], impaA[3], uri, ontModel);
    inicio.genAssetTh(u1, clAsThIt, dimint1, probA[4], impaA[4], uri, ontModel);
    inicio.genAssetTh(u2, clAsThNon, diminn1, probA[5], impaA[5], uri, ontModel);
    inicio.genAssetTh(u3, clAsThUs, diminu1, probA[6], impaA[6], uri, ontModel);
    inicio.genAssetTh(u4, clAsThSo, dimins1, probA[7], impaA[7], uri, ontModel);
  
    //inicio.genRs(ontModel, uri);
    //inicio.totalRisk(ontModel);
   
    inicio.genAn(classN, anCl, noIndividuos, fecha1, fecha2, uri, ontModel);
    
    inicio.genTh(prob, impa, classN, thCl, noIndividuos, uri, uri2, ontModel);
    inicio.genRs(ontModel, uri);
    //inicio.totalRisk(ontModel);
    /*
    eliminacion.eliminate(ontModel, 4, uri);
    inicio.calRsV(ontModel, uri);
    //inicio.totalRisk(ontModel);
   
    r1.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("H1.5"));
	r2.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("Cis1.5"));
	pc1.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("W2.0"));
	pc4.setPropertyValue(ontModel.getOntProperty(uri + "info"), ontModel.createTypedLiteral("W2.0"));
	eliminacion.changeAsset(ontModel);
	inicio.relationVul(uri, uri2, ontModel);
	inicio.genVul(r2, clVulThRouter, "NO_4", "3.0", "5.0", uri, uri2, ontModel);
	//inicio.calRsV(ontModel, uri);
	inicio.genRs(ontModel, uri);
    inicio.totalRisk(ontModel);
    */
    System.out.println("Funciono");
	
    try {
    	FileOutputStream f = new FileOutputStream("C:\\Users\\gonca\\Desktop\\Jaime Castro\\Cosas TFG\\TFG_base2.owl");
    	ontModel.write(f);
    	} catch (Error e) {
    	}
}

}
