import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Post-Quantum Security',
    Svg: require('@site/static/img/undraw_docusaurus_mountain.svg').default,
    description: (
      <>
        Built with PQXDH (Post-Quantum Extended Diffie-Hellman) protocol to ensure
        your communications remain secure even against future quantum computers.
      </>
    ),
  },
  {
    title: 'Decentralized Architecture',
    Svg: require('@site/static/img/undraw_docusaurus_tree.svg').default,
    description: (
      <>
        No single point of failure. Multiple relay servers can operate independently,
        providing resilience and reliability for your messaging infrastructure.
      </>
    ),
  },
  {
    title: 'Built with Rust',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        High performance and memory safety with Rust. Zero-copy operations,
        efficient serialization, and robust error handling throughout.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
