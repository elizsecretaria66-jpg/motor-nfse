const express = require('express');
const cors = require('cors');
const https = require('https');
const zlib = require('zlib');
const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

app.get('/', (req, res) => {
  res.json({ status: 'online', servico: 'Motor NFS-e Nacional' });
});

function extrairCertificadoPfx(pfxBase64, senha) {
  const cleanB64 = pfxBase64.replace(/^data:.*?;base64,/, '');
  const pfxDer = forge.util.decode64(cleanB64);
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senha);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]
    || p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];

  if (!certBags?.length || !keyBags?.length) {
    throw new Error('Não foi possível ler o certificado ou chave privada do PFX. Verifique a senha.');
  }

  const certPem = forge.pki.certificateToPem(certBags[0].cert);
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);
  const certClean = certPem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\r|\n/g, '');

  return { certPem, keyPem, certClean };
}

function gerarIdDps(cMun, cnpj, serie, nDps) {
  const mun = String(cMun || '4303103').padStart(7, '0');
  const doc = String(cnpj).replace(/\D/g, '').padStart(14, '0');
  const ser = String(serie || '1').padStart(5, '0');
  const num = String(nDps || Date.now()).slice(-15).padStart(15, '0');
  return `DPS${mun}2${doc}${ser}${num}`;
}

function assinarXmlDps(xml, certPem, keyPem, certClean, idDps) {
  const w3 = 'http:' + '//www.w3.org';
  const c14n = w3 + '/TR/2001/REC-xml-c14n-20010315';
  const rsaSha256 = w3 + '/2001/04/xmldsig-more#rsa-sha256';
  const sha256 = w3 + '/2001/04/xmlenc#sha256';
  const enveloped = w3 + '/2000/09/xmldsig#enveloped-signature';

  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    signatureAlgorithm: rsaSha256,
    canonicalizationAlgorithm: c14n
  });

  sig.addReference({
    xpath: `//*[@Id='${idDps}']`,
    digestAlgorithm: sha256,
    transforms: [enveloped, c14n]
  });

  sig.getKeyInfoContent = () => `<X509Data><X509Certificate>${certClean}</X509Certificate></X509Data>`;

  sig.computeSignature(xml, {
    location: { reference: `//*[@Id='${idDps}']`, action: 'after' }
  });

  return sig.getSignedXml();
}

app.post('/nfse', async (req, res) => {
  try {
    const { acao, ambiente, certificadoBase64, senhaCertificado, empresa, cliente, servico, dps } = req.body;

    if (!certificadoBase64 || !senhaCertificado) {
      return res.status(400).json({ sucesso: false, mensagem: 'Certificado A1 ou senha não informados.' });
    }

    const { certPem, keyPem, certClean } = extrairCertificadoPfx(certificadoBase64, senhaCertificado);

    const isProd = ambiente && ambiente.toLowerCase().includes('produ');
    const hostSefin = isProd ? 'sefin.nfse.gov.br' : 'sefin.producaorestrita.nfse.gov.br';
    const baseUrl = 'https:' + '//' + hostSefin + '/SefinNacional';

    const httpsAgent = new https.Agent({
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: true
    });

    if (acao === 'cancelar') {
      return res.json({ sucesso: false, mensagem: 'Fluxo de evento e101101 pronto para receber a chave de acesso de 50 dígitos.' });
    }

    const cnpjPrest = String(empresa?.cnpj || '').replace(/\D/g, '');
    const imPrest = String(empresa?.im || '').replace(/\D/g, '');
    const cMun = String(empresa?.ibge || '4303103');
    const docToma = String(cliente?.doc || '').replace(/\D/g, '');
    const tagDocToma = docToma.length === 14 ? 'CNPJ' : 'CPF';
    const nDps = String(Math.floor(Date.now() / 1000));
    const serie = '1';
    const idDps = gerarIdDps(cMun, cnpjPrest, serie, nDps);
    const dhEmi = new Date().toISOString().replace(/\.\d{3}Z$/, '-03:00');
    const dCompet = dps?.data || new Date().toISOString().split('T')[0];
    const valorServ = Number(dps?.valor || 0).toFixed(2);
    const cTribNac = String(servico?.codigo || '010101').replace(/\D/g, '').padStart(6, '0');
    const descServ = (dps?.descricao || servico?.nome || 'Prestacao de servicos').replace(/[<>&'"]/g, '');
    const nsNfse = 'http:' + '//www.sped.fazenda.gov.br/nfse';

    const xmlDps = `<?xml version="1.0" encoding="UTF-8"?>
<DPS xmlns="${nsNfse}" versao="1.00">
  <infDPS Id="${idDps}">
    <tpAmb>${isProd ? '1' : '2'}</tpAmb>
    <dhEmi>${dhEmi}</dhEmi>
    <verAplic>EmissorNacional_1.0</verAplic>
    <serie>${serie}</serie>
    <nDPS>${nDps}</nDPS>
    <dCompet>${dCompet}</dCompet>
    <tpEmit>1</tpEmit>
    <cLocEmi>${cMun}</cLocEmi>
    <prest>
      <CNPJ>${cnpjPrest}</CNPJ>
      ${imPrest ? `<IM>${imPrest}</IM>` : ''}
      <regTrib>
        <opSimpNac>1</opSimpNac>
        <regEspTrib>0</regEspTrib>
      </regTrib>
    </prest>
    ${docToma ? `<toma><${tagDocToma}>${docToma}</${tagDocToma}><xNome>${(cliente?.nome || 'Tomador').replace(/[<>&'"]/g, '')}</xNome></toma>` : ''}
    <serv>
      <locPrest><cLocPrestacao>${cMun}</cLocPrestacao></locPrest>
      <cServ>
        <cTribNac>${cTribNac}</cTribNac>
        <xDescServ>${descServ}</xDescServ>
      </cServ>
    </serv>
    <valores>
      <vServPrest><vServ>${valorServ}</vServ></vServPrest>
      <trib><tribMun><tribISSQN>1</tribISSQN><tpRetISSQN>1</tpRetISSQN></tribMun></trib>
    </valores>
  </infDPS>
</DPS>`;

    const xmlAssinado = assinarXmlDps(xmlDps, certPem, keyPem, certClean, idDps);
    const gzipBuffer = zlib.gzipSync(Buffer.from(xmlAssinado, 'utf-8'));
    const dpsXmlGZipB64 = gzipBuffer.toString('base64');

    const respostaSefin = await axios.post(
      `${baseUrl}/nfse`,
      { dpsXmlGZipB64 },
      { httpsAgent, headers: { 'Content-Type': 'application/json' } }
    );

    const dados = respostaSefin.data;
    return res.json({
      sucesso: true,
      numeroNfse: dados.nNFSe || nDps,
      chaveAcesso: dados.chaveAcesso || '',
      xmlAutorizado: dados.nfseXmlGZipB64 || ''
    });

  } catch (erro) {
    const detalhe = erro.response?.data?.erros?.[0]?.descricao
      || erro.response?.data?.mensagem
      || JSON.stringify(erro.response?.data)
      || erro.message;

    return res.status(200).json({
      sucesso: false,
      mensagem: detalhe
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Motor NFS-e Nacional rodando na porta ${PORT}`));
