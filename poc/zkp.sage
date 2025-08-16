from sagelib.arc_groups import G, GenG, GenH, hash_to_group, hash_to_scalar
from hash_to_field import I2OSP
from util import to_hex, to_bytes

from collections import namedtuple
ScalarVar = namedtuple("ScalarVar", "index")
ElementVar = namedtuple("ElementVar", "index")
Proof = namedtuple("Proof", "challenge responses")

class Proof(object):
    def __init__(self, challenge, responses):
        self.challenge = challenge
        self.responses = responses

    def serialize(self):
        output = G.serialize_scalar(self.challenge)
        for response in self.responses:
            output += G.serialize_scalar(response)
        return output

class ProofParticipant(object):
    def __init__(self, label):
        self.label = label
        self.scalar_labels = []
        self.elements = []
        self.element_labels = []
        self.constraints = []

    def constrain(self, result, linear_combination):
        self.constraints.append((result, linear_combination))

    def append_element(self, label, assignment):
        self.element_labels.append(to_bytes(label))
        self.elements.append(assignment)
        return ElementVar(len(self.elements) - 1)

def compose_challenge(label, elements, blinded_elements):
    challenge_input = to_bytes("")

    for element in elements:
        serialized_element = G.serialize(element)
        challenge_input += I2OSP(len(serialized_element), 2) + serialized_element

    for blinded_element in blinded_elements:
        serialized_blinded_element = G.serialize(blinded_element)
        challenge_input += I2OSP(len(serialized_blinded_element), 2) + serialized_blinded_element

    return hash_to_scalar(challenge_input, to_bytes(label))

class Prover(ProofParticipant):
    def __init__(self, label, rng, vectors):
        ProofParticipant.__init__(self, label)
        self.rng = rng
        self.vectors = vectors
        self.scalars = []
    
    def append_scalar(self, label, assignment):
        self.scalar_labels.append(to_bytes(label))
        self.scalars.append(assignment)
        return ScalarVar(len(self.scalars) - 1)

    def prove(self):
        # blindings = [G.random_scalar(self.rng) for i in range(len(self.scalars))]
        blindings = [i+1 for i in range(len(self.scalars))]
        for i, b in enumerate(blindings):
            self.vectors["Blinding_{}".format(i)] = to_hex(G.serialize_scalar(b))
        return self.prove_with_randomness(blindings)

    def prove_with_randomness(self, blindings):
        if len(self.scalars) != len(self.scalar_labels) or len(self.elements) != len(self.element_labels):
            raise Exception("invalid proof configuration")
        
        if len(blindings) != len(self.scalars):
            raise Exception("invalid blindings")

        # For each constraint, compute the blinded version of the constraint element.
        # Example: if the constraint is A=x*B, compute ABlind=xBlind*B for blinding scalar xBlind.
        # Example: if the constraint is A=x*B+y*C, compute ABlind=xBlind*B + yBlind*C for blinding scalars xBlind, yBlind.
        blinded_elements = []
        for (constraint_point, linear_combination) in self.constraints:
            if constraint_point.index > len(self.elements):
                raise Exception("invalid variable allocation")

            for (scalar_var, element_var) in linear_combination:
                if scalar_var.index > len(self.scalars):
                    raise Exception("invalid variable allocation")
                if element_var.index > len(self.elements):
                    raise Exception("invalid variable allocation")

            scalar_index = linear_combination[0][0].index
            element_index = linear_combination[0][1].index
            blinded_element = blindings[scalar_index] * self.elements[element_index]

            for i, pair in enumerate(linear_combination):
                if i > 0:
                    scalar_index = pair[0].index
                    element_index = pair[1].index
                    blinded_element += blindings[scalar_index] * self.elements[element_index]

            blinded_elements.append(blinded_element)

        # Obtain a scalar challenge
        challenge = compose_challenge(self.label, self.elements, blinded_elements)

        # Compute response scalars from the challenge, scalars, and blindings.
        responses = []
        for (index, scalar) in enumerate(self.scalars):
            blinding = blindings[index]
            responses.append(blinding - challenge * scalar)

        return Proof(challenge, responses)

class Verifier(ProofParticipant):
    def __init__(self, label):
        ProofParticipant.__init__(self, label)

    def append_scalar(self, label):
        self.scalar_labels.append(to_bytes(label))
        return ScalarVar(len(self.scalar_labels) - 1)

    def verify(self, proof):
        if len(self.elements) != len(self.element_labels):
            raise Exception("invalid proof fields")
        
        blinded_elements = []
        for (constraint_element, linear_combination) in self.constraints:
            if constraint_element.index > len(self.elements):
                raise Exception("invalid variable allocation")
            for (_, element_var) in linear_combination:
                if element_var.index > len(self.elements):
                    raise Exception("invalid variable allocation")

            challenge_element = proof.challenge * self.elements[constraint_element.index]
            for i, pair in enumerate(linear_combination):
                challenge_element += proof.responses[pair[0].index] * self.elements[pair[1].index]
            
            blinded_elements.append(challenge_element)

        challenge = compose_challenge(self.label, self.elements, blinded_elements)
        return challenge == proof.challenge

