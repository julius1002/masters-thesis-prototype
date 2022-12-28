package de.tu.bs.cs.ias.thesis.shared;

import de.tu.bs.cs.ias.thesis.aws.AWSKMSClient;

import java.util.List;
import java.util.Optional;

public record KeyOptions(
        Optional<String> keyVersion,
        Optional<String> chosenKeyName,
        Optional<String> keyRingId,
        Optional<String> cryptoKeyId,

        // aws
        Optional<AWSKMSClient.EncryptionAlgorithm> encAlgoRithm,
        Optional<String> encryptionContext,
        List<String> grantTokens,
        Optional<String> keyId
) {

}
